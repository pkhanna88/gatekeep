"""
Day 6 acceptance: key rotation, and the `kid` handling that makes it work.

Section 3.5: "Plan rotation on Day 6, not later. Retrofitting kid-based key
selection into a working system is unpleasant." This is that plan, executed and
asserted rather than written down and hoped for.

The property that matters is narrow and easy to state:

    After rotating, a token minted BEFORE the rotation still verifies - but only
    against the key version it was signed with.

That is what lets us rotate on a Tuesday afternoon without coordinating with
anything. Tokens live five minutes; five minutes after a rotation there is
nothing left signed under the old key. No drain, no dual-write, no downtime.

These tests rotate a THROWAWAY key, never `gk-signing`.

That is not tidiness. Rotating the live key makes the token service mint tokens
with a new `kid`, and the PEP's JWKS cache refetches on an unknown `kid` at most
once every 10 seconds - a deliberate guard so a forged `kid` cannot make us
hammer the token service. Inside that window every new token is refused with
`unknown_signing_key`. Running these tests immediately before the demo took the
whole demo down for exactly that reason. The guard is correct; rotating
production state from a test was not.
"""

import base64
import json

import httpx
import pytest
from app import settings
from jwt import algorithms, decode
from token_service.signing import TransitSigner, kid_for, version_from_kid

# NEVER the live key - see the note at the top of this file.
KEY_NAME = "gk-signing-rotation-test"

OPENBAO = "http://localhost:8200"
HEADERS = {"X-Vault-Token": "root"}

FAR_FUTURE = 4102444800  # 2100-01-01, so expiry never interferes


@pytest.fixture
def signer():
    """A signer pointed at a throwaway key, created and destroyed per test.

    `settings.SIGNING_KEY` is redirected for the duration so both kid_for() and
    TransitSigner() follow it. The live `gk-signing` is never rotated.
    """
    try:
        httpx.get(f"{OPENBAO}/v1/sys/health", timeout=10)
    except httpx.ConnectError:
        pytest.skip("OpenBao is not reachable")

    r = httpx.post(
        f"{OPENBAO}/v1/transit/keys/{KEY_NAME}",
        headers=HEADERS,
        json={"type": "rsa-2048"},
        timeout=30,
    )
    if r.status_code not in (200, 204):
        pytest.skip(f"Could not create the test key: HTTP {r.status_code}")

    original = settings.SIGNING_KEY
    settings.SIGNING_KEY = KEY_NAME
    try:
        yield TransitSigner()
    finally:
        settings.SIGNING_KEY = original
        httpx.post(
            f"{OPENBAO}/v1/transit/keys/{KEY_NAME}/config",
            headers=HEADERS,
            json={"deletion_allowed": True},
            timeout=10,
        )
        httpx.delete(f"{OPENBAO}/v1/transit/keys/{KEY_NAME}", headers=HEADERS, timeout=10)


def _verify(token: str, jwk: dict) -> bool:
    key = algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    try:
        decode(token, key, algorithms=["RS256"])
        return True
    except Exception:
        return False


def _kid_of(token: str) -> str:
    header = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["kid"]


# --- the kid scheme --------------------------------------------------------


def test_kid_round_trips():
    """`kid` is the transit key version stated out loud, not an opaque label.
    That is the entire rotation design - no separate mapping to keep in sync."""
    assert version_from_kid(kid_for(7)) == 7


def test_kid_from_another_issuer_is_rejected():
    with pytest.raises(ValueError):
        version_from_kid("some-other-service-v1")


# --- signing ---------------------------------------------------------------


async def test_token_verifies_against_its_own_published_key(signer):
    token = await signer.sign_jwt({"sub": "priya@acme.test", "exp": FAR_FUTURE})
    jwks = await signer.jwks()
    by_kid = {k["kid"]: k for k in jwks["keys"]}

    kid = _kid_of(token)
    assert kid in by_kid, f"Token carries kid {kid} which JWKS does not publish"
    assert _verify(token, by_kid[kid]), "Token did not verify against its own published key"


async def test_signature_is_base64url_not_vaults_own_format(signer):
    """Transit hands back `vault:v1:<standard base64>`. A JWT needs raw
    base64url with no padding. Skipping that conversion produces a token that
    looks completely well-formed and fails every verification."""
    token = await signer.sign_jwt({"sub": "x", "exp": FAR_FUTURE})
    signature = token.split(".")[2]
    assert not signature.startswith("vault:"), "Vault's wrapper leaked into the JWT"
    assert "=" not in signature, "base64url in a JWT is unpadded"
    assert "+" not in signature and "/" not in signature, "standard base64, not base64url"


async def test_jwks_publishes_every_live_version(signer):
    jwks = await signer.jwks()
    async with httpx.AsyncClient(timeout=10) as c:
        data = (await c.get(f"{OPENBAO}/v1/transit/keys/{KEY_NAME}", headers=HEADERS)).json()[
            "data"
        ]

    floor = int(data.get("min_decryption_version") or 1)
    expected = {kid_for(int(v)) for v in data["keys"] if int(v) >= floor}
    assert {k["kid"] for k in jwks["keys"]} == expected
    for k in jwks["keys"]:
        assert k["kty"] == "RSA" and k["alg"] == "RS256" and k["use"] == "sig"
        assert k["n"] and k["e"], "JWK is missing the public key material"


# --- rotation, which is the point of the day -------------------------------


async def test_rotation_keeps_old_tokens_verifiable(signer):
    """The whole rotation story in one test.

    Mint a token. Rotate. The old token must still verify against the key
    version it was signed with, and must NOT verify against the new one.
    """
    before = await signer.latest_version()
    old_token = await signer.sign_jwt({"sub": "priya@acme.test", "exp": FAR_FUTURE})
    assert _kid_of(old_token) == kid_for(before)

    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{OPENBAO}/v1/transit/keys/{KEY_NAME}/rotate", headers=HEADERS, json={})
        r.raise_for_status()

    after = await signer.latest_version()
    assert after == before + 1, f"Rotation did not advance the key ({before} -> {after})"

    jwks = {k["kid"]: k for k in (await signer.jwks())["keys"]}
    assert kid_for(before) in jwks, "Rotation dropped the old key from JWKS - old tokens die"
    assert kid_for(after) in jwks, "New key is not published"

    assert _verify(old_token, jwks[kid_for(before)]), (
        "A token minted before the rotation no longer verifies. Rotation would "
        "break every token in flight."
    )
    assert not _verify(old_token, jwks[kid_for(after)]), (
        "The old token verified against the NEW key, which means kid selection "
        "is not actually selecting anything."
    )

    new_token = await signer.sign_jwt({"sub": "priya@acme.test", "exp": FAR_FUTURE})
    assert _kid_of(new_token) == kid_for(after), "New tokens are not using the rotated key"
    assert _verify(new_token, jwks[kid_for(after)])


async def test_signing_an_archived_version_is_not_silently_downgraded(signer):
    """Pinning a version is deliberate; it must actually pin.

    The rotation runbook's verification step signs with a specific version to
    confirm a key still works before cutting over, so this has to be exact.
    """
    # The fixture hands over a fresh key at v1, so make a second version to pin
    # against rather than skipping.
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"{OPENBAO}/v1/transit/keys/{KEY_NAME}/rotate", headers=HEADERS, json={})
        r.raise_for_status()

    latest = await signer.latest_version()
    assert latest >= 2, "rotation did not create a second version to pin against"

    token = await signer.sign_jwt({"sub": "x", "exp": FAR_FUTURE}, version=latest - 1)
    assert _kid_of(token) == kid_for(latest - 1), (
        "Pinning a version was silently ignored - the runbook's verification "
        "step signs with a specific version before cutting over, so it must pin."
    )
