"""
The PEP pipeline. Section 7.2. Every agent request to a target system passes here.

    1. verify token        signature (JWKS), RS256 only, iss, aud, exp (+30s leeway)
    2. revocation          Redis revoked set, then Postgres grant status - fail closed
    3. map request         connector turns HTTP into system:type:action:id
    4. scope               the token's scope must contain that exact string   (Invariant 2 at use)
    5. policy              OpenFGA: does the HUMAN still hold it, right now
    6. forward             only now does anything reach upstream
    7. audit allow         SHA-256 digest of the response, never the body

Every step before forward can refuse by raising Denied, and every refusal is
written to the audit chain with its reason. Any exception we did not anticipate
also denies (503) - the catch-all at the bottom is the most important block in
this file. There is no path from an error to a forwarded request.

One more rule: if the allow cannot be audited, the response is not returned.
No evidence, no data.

Per section 9.2, changes to this file need a second reviewer.
"""

from __future__ import annotations

import hashlib
import logging
import time

from app import events, settings
from app.fga import PolicyUnavailable
from app.jwtverify import InvalidToken, bearer, verify
from app.revocation import grant_state
from fastapi import Request
from fastapi.responses import JSONResponse, Response

from pep_proxy.connectors.base import Action, UnmappedRequest
from pep_proxy.connectors.mock import MAX_BODY_BYTES

log = logging.getLogger("gatekeep.pep")

# Human-readable text for every denial reason (Day 18). The code is for machines.
MESSAGES = {
    "missing_bearer_token": "No token presented. Every request needs a Gatekeep agent token.",
    "malformed_token": "The token is not a valid JWT.",
    "unsupported_algorithm": "Token is not signed with RS256.",
    "unknown_signing_key": "Token was signed by a key Gatekeep does not publish.",
    "bad_signature": "Token signature does not verify. It was altered or forged.",
    "token_expired": "Token has expired. Tokens live five minutes; exchange the grant again.",
    "wrong_audience": "Token was not issued for the Gatekeep PEP.",
    "wrong_issuer": "Token was not issued by the Gatekeep token service.",
    "invalid_token": "Token failed validation.",
    "jwks_unavailable": "Cannot fetch signing keys to verify the token.",
    "invalid_claims": "Token is missing required delegation claims.",
    "grant_revoked": "The grant behind this token has been revoked.",
    "grant_expired": "The grant behind this token has expired.",
    "grant_not_found": "The grant behind this token does not exist.",
    "unknown_system": "No connector for that target system.",
    "unmapped_request": "Gatekeep does not recognise this request, so it is refused.",
    "request_too_large": "Request body exceeds the size limit.",
    "action_outside_token_scope": "The token does not cover this record and action.",
    "policy_denied": "The human who granted this no longer holds access to this record.",
}


class Denied(Exception):
    def __init__(self, reason: str, status: int = 403):
        super().__init__(reason)
        self.reason, self.status = reason, status


def _message(reason: str) -> str:
    if reason.startswith("grant_"):
        return MESSAGES.get(reason, f"The grant behind this token is not usable ({reason}).")
    return MESSAGES.get(reason, reason)


async def handle(system: str, path: str, request: Request) -> Response:
    state = request.app.state
    started = time.perf_counter()
    fields: dict = {}  # audit fields, filled in as we learn them
    action: Action | None = None

    def done(response: Response, decision: str) -> Response:
        response.headers["X-Gatekeep-Decision"] = decision
        response.headers["X-Gatekeep-Latency-Ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
        return response

    try:
        # 1. Token
        try:
            claims = await verify(
                bearer(request.headers.get("authorization")),
                state.agent_jwks,
                issuer=settings.AGENT_TOKEN_ISSUER,
                audience=settings.AGENT_TOKEN_AUDIENCE,
                required=["sub", "act", "grant_id", "scope", "jti"],
            )
        except InvalidToken as e:
            raise Denied(e.reason, 401) from e
        act, scope = claims.get("act"), claims.get("scope")
        if (
            not isinstance(act, dict)
            or not isinstance(act.get("sub"), str)
            or not isinstance(scope, list)
            or not all(isinstance(s, str) for s in scope)
            or not isinstance(claims.get("grant_id"), str)
        ):
            raise Denied("invalid_claims", 401)
        fields = {
            "principal_sub": claims["sub"],
            "agent_id": act["sub"],
            "session_id": act.get("instance"),
            "grant_id": claims["grant_id"],
        }

        # 2. Revocation - every request, not just at issue
        usable, reason = await grant_state(state.pool, state.redis, claims["grant_id"])
        if not usable:
            raise Denied(reason)

        # 3. Map to a scope-shaped action
        connector = state.connectors.get(system)
        if connector is None:
            raise Denied("unknown_system")
        try:
            action = connector.map_request(request.method, path)
        except UnmappedRequest as e:
            raise Denied("unmapped_request") from e
        fields.update(resource=action.fga_object, action=action.verb)
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise Denied("request_too_large", 413)

        # 4. Token scope must cover it - exact match, no wildcards
        if action.scope not in scope:
            raise Denied("action_outside_token_scope")

        # 5. Policy at access time: rights can be withdrawn after approval
        if not await state.fga.check(f"user:{claims['sub']}", action.relation, action.fga_object):
            raise Denied("policy_denied")

        # 6. Forward
        upstream = await connector.forward(action, request.method, body)

        # 7. Evidence first, then the data
        await events.record(
            state.pool,
            event_type="access.allowed",
            decision="allow",
            payload_digest=hashlib.sha256(upstream.content).hexdigest(),
            **fields,
        )
        return done(
            Response(
                upstream.content, status_code=upstream.status, media_type=upstream.content_type
            ),
            "allow",
        )

    except Denied as d:
        await events.record(
            state.pool, event_type="access.denied", decision="deny", reason=d.reason, **fields
        )
        return done(
            JSONResponse(
                status_code=d.status, content={"error": d.reason, "message": _message(d.reason)}
            ),
            "deny",
        )

    except Exception as e:
        # Unknown failure: deny, try to log it, never fall through to forwarding.
        # PolicyUnavailable, Redis+Postgres down, upstream errors - all land here.
        log.exception("pep_internal_error")
        reason = "policy_unavailable" if isinstance(e, PolicyUnavailable) else "internal_error"
        try:
            await events.record(
                state.pool, event_type="access.denied", decision="deny", reason=reason, **fields
            )
        except Exception:
            log.exception("pep_could_not_audit_denial")
        return done(
            JSONResponse(
                status_code=503,
                content={
                    "error": "authorization_unavailable",
                    "message": "Gatekeep could not complete the authorization check, "
                    "so the request was refused.",
                },
            ),
            "deny",
        )
