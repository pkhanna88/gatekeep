"""
RFC 8693 token exchange and Invariant 2. Sections 2.9, 6.2, 6.3.

    POST /oauth/token   (application/x-www-form-urlencoded)
      grant_type          = urn:ietf:params:oauth:grant-type:token-exchange
      subject_token       = <grant id>                  whose authority
      subject_token_type  = urn:gatekeep:params:token-type:grant
      actor_token         = <agent bootstrap credential> who is acting
      actor_token_type    = urn:gatekeep:params:token-type:agent
      scope               = optional, space separated - ask for LESS than the grant
      session_id          = optional - refresh an existing run instead of starting one

Checks, in order, each refusal audited as `token.denied` with its reason:

  1. Request is well formed (types, grant_type)
  2. Actor credential verifies (argon2id) and the agent is active
  3. Grant exists and was issued to THIS agent
  4. Grant is usable right now: Redis revoked set, then Postgres status/expiry
  5. INVARIANT 2: requested scope is a subset of the grant's scope
  6. If refreshing, the session belongs to this grant and is still running

Every refresh walks the same checks - refresh is a policy checkpoint, not a
formality (section 2.10). That is how revocation stops an agent even when it
never touches the PEP.

The token: `sub` is the human, `act.sub` is the agent (section 6.3). Lifetime is
five minutes, or less if the grant expires sooner - a token may never outlive
the authority it came from.

Per section 9.2, changes to this file need a second reviewer.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from app import events, ids, settings
from app.agents import authenticate_agent
from app.errors import ApiError
from app.revocation import grant_state
from app.scopes import ScopeError, is_subset, parse_scopes
from fastapi import APIRouter, Form, Request

from token_service.signing import SigningUnavailable

router = APIRouter(tags=["token exchange"])

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_TYPE_URN = "urn:gatekeep:params:token-type:grant"
AGENT_TYPE_URN = "urn:gatekeep:params:token-type:agent"
ACCESS_TOKEN_URN = "urn:ietf:params:oauth:token-type:access_token"


async def _deny(pool, status: int, reason: str, message: str, **audit_fields) -> ApiError:
    """Audit the refusal, then hand back the error for the caller to raise."""
    await events.record(
        pool, event_type="token.denied", decision="deny", reason=reason, **audit_fields
    )
    return ApiError(status, reason, message)


@router.post("/oauth/token")
async def token_exchange(
    request: Request,
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    subject_token_type: str = Form(...),
    actor_token: str = Form(...),
    actor_token_type: str = Form(...),
    scope: str | None = Form(None),
    session_id: str | None = Form(None),
):
    pool, redis, signer = request.app.state.pool, request.app.state.redis, request.app.state.signer

    # 1. Shape
    if grant_type != TOKEN_EXCHANGE:
        raise ApiError(400, "unsupported_grant_type", f"grant_type must be {TOKEN_EXCHANGE}")
    if subject_token_type != GRANT_TYPE_URN or actor_token_type != AGENT_TYPE_URN:
        raise ApiError(400, "invalid_request", "Unsupported subject_token_type or actor_token_type")

    # 2. Who is acting
    agent = await authenticate_agent(pool, actor_token)
    if agent is None:
        raise await _deny(
            pool,
            401,
            "invalid_actor",
            "Agent bootstrap credential rejected",
            grant_id=subject_token,
        )

    # 3. On whose authority
    grant = await pool.fetchrow("SELECT * FROM grants WHERE id = $1", subject_token)
    fields = {"grant_id": subject_token, "agent_id": agent["id"]}
    if grant is None:
        raise await _deny(pool, 400, "grant_not_found", f"No grant {subject_token}", **fields)
    fields["principal_sub"] = grant["principal_sub"]
    if grant["agent_id"] != agent["id"]:
        raise await _deny(
            pool,
            403,
            "grant_not_issued_to_this_agent",
            "This grant was issued to a different agent",
            **fields,
        )

    # 4. Is the authority still live - revoked set first, Postgres is the truth
    try:
        usable, reason = await grant_state(pool, redis, grant["id"])
    except Exception as e:  # cannot verify revocation, so cannot issue
        raise ApiError(503, "revocation_unavailable", f"Cannot verify grant status: {e}") from e
    if not usable:
        raise await _deny(pool, 403, reason, f"Grant is not usable: {reason}", **fields)

    # 5. INVARIANT 2 - issued scope never exceeds grant scope
    granted = list(grant["scopes"])
    if scope:
        try:
            requested = [str(s) for s in parse_scopes(scope.split())]
        except ScopeError as e:
            raise await _deny(pool, 400, "invalid_scope", str(e), **fields) from e
        outside = is_subset(requested, granted)
        if outside:
            raise await _deny(
                pool,
                403,
                "scope_exceeds_grant",
                f"Requested scope not in grant: {', '.join(outside)}",
                **fields,
            )
    else:
        requested = granted

    # 6. New session, or a refresh of an existing one
    if session_id:
        session = await pool.fetchrow("SELECT * FROM agent_sessions WHERE id = $1", session_id)
        if session is None or session["grant_id"] != grant["id"] or session["status"] != "running":
            raise await _deny(
                pool,
                403,
                "session_not_running",
                "Session does not exist, belongs to another grant, or was stopped",
                session_id=session_id,
                **fields,
            )
        event_type, started_at = "token.refreshed", session["started_at"]
    else:
        session_id = ids.session_id()
        started_at = datetime.now(UTC)
        await pool.execute(
            "INSERT INTO agent_sessions (id, grant_id, agent_id, started_at, status) "
            "VALUES ($1, $2, $3, $4, 'running')",
            session_id,
            grant["id"],
            agent["id"],
            started_at,
        )
        event_type = "token.issued"

    now = int(time.time())
    exp = min(now + settings.AGENT_TOKEN_TTL_SECONDS, int(grant["expires_at"].timestamp()))
    claims = {
        "iss": settings.AGENT_TOKEN_ISSUER,
        "sub": grant["principal_sub"],
        "act": {"sub": agent["id"], "instance": session_id, "spawned_at": started_at.isoformat()},
        "aud": settings.AGENT_TOKEN_AUDIENCE,
        "grant_id": grant["id"],
        "purpose": grant["purpose"],
        "scope": requested,
        "constraints": grant["constraints"],
        "iat": now,
        "exp": exp,
        "jti": ids.token_id(),
    }
    try:
        token = await signer.sign_jwt(claims)
    except SigningUnavailable as e:
        raise ApiError(503, "signing_unavailable", str(e)) from e

    await events.record(
        pool, event_type=event_type, session_id=session_id, decision="allow", **fields
    )
    return {
        "access_token": token,
        "issued_token_type": ACCESS_TOKEN_URN,
        "token_type": "Bearer",
        "expires_in": exp - now,
        "session_id": session_id,
        "scope": " ".join(requested),
    }
