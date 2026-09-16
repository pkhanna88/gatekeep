"""
JWT verification against a remote JWKS. Used twice:

  - control plane verifies HUMAN tokens from Keycloak
  - PEP verifies AGENT tokens from our token service

Same rules both times (section 4.4 - we trust nothing, verify at every boundary):
signature, one allowed algorithm, issuer, audience, expiry, with 30 seconds of
leeway for clock skew (section 3.3).

`algorithms=["RS256"]` is pinned rather than read from the token header, which
closes the classic alg-confusion attack where a token claims `none` or `HS256`.
"""

from __future__ import annotations

import time

import httpx
import jwt
from jwt import PyJWK

from app import settings


class InvalidToken(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


class JWKSCache:
    """Fetch keys once, refetch on an unknown `kid` (key rotation), at most every 10s."""

    def __init__(self, url: str, client: httpx.AsyncClient | None = None):
        self.url = url
        self._client = client or httpx.AsyncClient(timeout=5.0)
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at = 0.0

    async def _refresh(self) -> None:
        r = await self._client.get(self.url)
        r.raise_for_status()
        keys = {}
        for jwk in r.json().get("keys", []):
            if jwk.get("use", "sig") == "sig" and jwk.get("kid"):
                try:
                    keys[jwk["kid"]] = PyJWK(jwk)
                except jwt.PyJWTError:
                    continue  # e.g. an encryption-only key Keycloak also publishes
        self._keys, self._fetched_at = keys, time.monotonic()

    async def get(self, kid: str) -> PyJWK:
        if kid not in self._keys and time.monotonic() - self._fetched_at > 10:
            try:
                await self._refresh()
            except httpx.HTTPError as e:
                raise InvalidToken("jwks_unavailable", str(e)) from e
        key = self._keys.get(kid)
        if key is None:
            raise InvalidToken("unknown_signing_key", f"no key with kid {kid!r}")
        return key


async def verify(
    token: str, jwks: JWKSCache, *, issuer: str, audience: str, required: list[str]
) -> dict:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise InvalidToken("malformed_token", str(e)) from e
    if header.get("alg") != "RS256":
        raise InvalidToken("unsupported_algorithm", f"alg {header.get('alg')!r}")
    key = await jwks.get(header.get("kid", ""))
    try:
        return jwt.decode(
            token,
            key=key.key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            leeway=settings.CLOCK_LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", *required]},
        )
    except jwt.ExpiredSignatureError as e:
        raise InvalidToken("token_expired", str(e)) from e
    except jwt.InvalidSignatureError as e:
        raise InvalidToken("bad_signature", str(e)) from e
    except jwt.InvalidAudienceError as e:
        raise InvalidToken("wrong_audience", str(e)) from e
    except jwt.InvalidIssuerError as e:
        raise InvalidToken("wrong_issuer", str(e)) from e
    except jwt.PyJWTError as e:
        raise InvalidToken("invalid_token", str(e)) from e


def bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise InvalidToken("missing_bearer_token")
    token = authorization[7:].strip()
    if not token:
        raise InvalidToken("missing_bearer_token")
    return token
