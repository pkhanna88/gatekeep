"""
Human authentication for the control plane: verify a Keycloak access token.

Section 4.4, Human -> Console / Console -> Control Plane: we trust nothing and
verify signature, issuer, expiry and audience. The identity we act on is the
`principal` claim (the email), never `sub` - see docs/DECISIONS.md "Day 1 fix":
Keycloak's `sub` is an opaque UUID and every tuple and grant is keyed by email.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, Request

from app import settings
from app.errors import ApiError
from app.jwtverify import InvalidToken, bearer, verify

ROLE_ANALYST = "analyst"
ROLE_ADMIN = "security-admin"
ROLE_AUDITOR = "auditor"


@dataclass(frozen=True)
class Human:
    principal: str
    roles: frozenset[str]

    @property
    def sees_everything(self) -> bool:
        return bool(self.roles & {ROLE_ADMIN, ROLE_AUDITOR})


async def current_human(request: Request, authorization: str | None = Header(None)) -> Human:
    try:
        claims = await verify(
            bearer(authorization),
            request.app.state.keycloak_jwks,
            issuer=settings.KEYCLOAK_ISSUER,
            audience=settings.HUMAN_AUDIENCE,
            required=["principal"],
        )
    except InvalidToken as e:
        raise ApiError(401, "unauthenticated", f"Human token rejected: {e.reason}") from e
    principal = claims.get("principal")
    if not isinstance(principal, str) or "@" not in principal:
        raise ApiError(401, "unauthenticated", "Human token has no usable principal claim")
    roles = frozenset((claims.get("realm_access") or {}).get("roles") or [])
    return Human(principal=principal, roles=roles)


def require_role(human: Human, *roles: str) -> None:
    if not human.roles & set(roles):
        raise ApiError(
            403,
            "forbidden",
            f"Requires one of the roles {sorted(roles)}; you have {sorted(human.roles)}",
        )
