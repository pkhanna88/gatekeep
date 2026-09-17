"""
Signing through OpenBao transit. Section 3.5.

The private key never enters this process. We build the JWT signing input
(`base64url(header).base64url(payload)`), send it to transit, and get back a
signature. A process that cannot read the key cannot leak it.

Two details that cost time if you do not know them (tests/test_signing_key.py):

  - Transit returns `vault:v<N>:<standard base64>`. A JWT wants the raw
    signature in base64url without padding, so we strip and re-encode.
  - `kid` is derived from the transit key version: gk-signing-v<N>. We pin
    `key_version` on the sign call to the version named in the header, so the
    two can never disagree even if a rotation lands mid-request.
"""

from __future__ import annotations

import base64
import json

import httpx
from app import settings
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class SigningUnavailable(RuntimeError):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def kid_for(version: int) -> str:
    return f"{settings.SIGNING_KEY}-v{version}"


def version_from_kid(kid: str) -> int:
    """Inverse of kid_for. Raises on a kid this service did not mint.

    Rotation tooling needs to go from a token back to the key version that
    signed it - docs/KEY-ROTATION.md section 8 walks through a verifier
    rejecting a valid token, and "which version was this?" is the first question.
    """
    prefix = f"{settings.SIGNING_KEY}-v"
    if not kid.startswith(prefix):
        raise ValueError(f"kid {kid!r} was not issued by this service")
    return int(kid[len(prefix) :])


class TransitSigner:
    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client or httpx.AsyncClient(
            base_url=settings.BAO_URL, headers={"X-Vault-Token": settings.BAO_TOKEN}, timeout=5.0
        )

    async def _key(self) -> dict:
        try:
            r = await self._client.get(f"/v1/transit/keys/{settings.SIGNING_KEY}")
        except httpx.HTTPError as e:
            raise SigningUnavailable(f"OpenBao unreachable: {e}") from e
        if r.status_code != 200:
            raise SigningUnavailable(
                f"Signing key unavailable (HTTP {r.status_code}). Run `make seed`."
            )
        return r.json()["data"]

    async def latest_version(self) -> int:
        """The version new tokens are being signed with right now."""
        return int((await self._key())["latest_version"])

    async def sign_jwt(self, payload: dict, *, version: int | None = None) -> str:
        """Sign with the current key, or a pinned version.

        Pinning is for tests and for the rotation runbook's verification step -
        confirming a specific key version still signs before cutting over to it.
        Production always passes None and gets the latest.
        """
        if version is None:
            version = int((await self._key())["latest_version"])
        header = {"alg": "RS256", "typ": "JWT", "kid": kid_for(version)}
        signing_input = (
            f"{b64url(json.dumps(header, separators=(',', ':')).encode())}."
            f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
        )
        try:
            r = await self._client.post(
                f"/v1/transit/sign/{settings.SIGNING_KEY}",
                json={
                    "input": base64.b64encode(signing_input.encode()).decode(),
                    "key_version": version,
                    "hash_algorithm": "sha2-256",
                    "signature_algorithm": "pkcs1v15",  # RS256 = RSASSA-PKCS1-v1_5 + SHA-256
                },
            )
        except httpx.HTTPError as e:
            raise SigningUnavailable(f"OpenBao unreachable: {e}") from e
        if r.status_code != 200:
            raise SigningUnavailable(f"Transit refused to sign: HTTP {r.status_code}")
        prefix, ver, sig = r.json()["data"]["signature"].split(":", 2)
        if prefix != "vault" or ver != f"v{version}":
            raise SigningUnavailable(f"Unexpected signature envelope {prefix}:{ver}")
        return f"{signing_input}.{b64url(base64.b64decode(sig))}"

    async def jwks(self) -> dict:
        """Every key version's public half, so tokens signed before a rotation still verify."""
        data = await self._key()
        keys = []
        for version, info in sorted(data["keys"].items(), key=lambda kv: int(kv[0])):
            if int(version) < int(data.get("min_decryption_version", 1)):
                continue
            numbers = load_pem_public_key(info["public_key"].encode()).public_numbers()
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid_for(int(version)),
                    "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                }
            )
        return {"keys": keys}

    async def aclose(self) -> None:
        await self._client.aclose()
