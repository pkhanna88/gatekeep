"""
Day 6 groundwork (INF): the token-signing key exists and cannot be extracted.

§3.5 is unambiguous about this key: it is the most sensitive material in the
system, anyone holding it can forge a token granting any authority to any agent,
and it must never sit in an environment variable. OpenBao's transit engine signs
on our behalf and does not release it.

Until Day 7 that was aspiration - transit was not mounted and no key existed.
`make seed` now creates it, and this file asserts the property that makes the
arrangement worth anything: signing works, export is refused.

BE2 owns the token service. This is the substrate it will sign against, standing
up before Day 6 rather than during it.
"""

import base64

import httpx
import pytest

OPENBAO = "http://localhost:8200"
TOKEN = "root"
KEY = "gk-signing"

HEADERS = {"X-Vault-Token": TOKEN}

NOT_SEEDED = (
    f"No transit key named {KEY!r}. Run `make seed`. OpenBao runs in dev mode and "
    f"loses everything on restart (§3.5), so a restarted stack needs re-seeding."
)


@pytest.fixture(scope="session")
def key() -> dict:
    try:
        r = httpx.get(f"{OPENBAO}/v1/transit/keys/{KEY}", headers=HEADERS, timeout=10)
    except httpx.ConnectError:
        pytest.skip("OpenBao is not reachable")
    if r.status_code == 404:
        pytest.skip(NOT_SEEDED)
    r.raise_for_status()
    return r.json()["data"]


def test_transit_engine_is_mounted():
    """A bare OpenBao passes its health check and signs nothing."""
    try:
        r = httpx.get(f"{OPENBAO}/v1/sys/mounts", headers=HEADERS, timeout=10)
    except httpx.ConnectError:
        pytest.skip("OpenBao is not reachable")
    r.raise_for_status()
    mounts = r.json().get("data") or r.json()
    assert (
        "transit/" in mounts
    ), f"transit is not mounted. Mounts: {sorted(mounts)}. Run `make seed`."


def test_signing_key_is_an_rsa_key_suitable_for_rs256(key):
    """§2.4's header says alg RS256, so the key has to be RSA."""
    assert key["type"] == "rsa-2048", f"Expected rsa-2048, got {key['type']!r}"


def test_key_material_cannot_be_exported(key):
    """The whole reason transit is worth using.

    §3.5: 'Do not fetch the key and sign locally. That defeats the purpose.'
    An exportable key turns transit into an expensive environment variable.
    """
    assert key["exportable"] is False, "The signing key is marked exportable"

    r = httpx.get(f"{OPENBAO}/v1/transit/export/signing-key/{KEY}", headers=HEADERS, timeout=10)
    assert r.status_code >= 400, (
        f"OpenBao returned HTTP {r.status_code} for an export of the signing key. "
        f"It should refuse. If this ever succeeds, the private key can leave the "
        f"vault and every token in the estate becomes forgeable."
    )


def test_public_key_is_retrievable_for_jwks(key):
    """The token service publishes JWKS at /.well-known/jwks.json (§4.3). The
    public half has to come from somewhere, and this is it."""
    versions = key["keys"]
    assert versions, "Key has no versions"
    latest = versions[str(key["latest_version"])]
    assert "public_key" in latest, f"No public key on version {key['latest_version']}"
    assert latest["public_key"].startswith("-----BEGIN PUBLIC KEY-----")


def test_transit_will_actually_sign(key):
    """End to end through the API the token service will call."""
    payload = base64.b64encode(b"gatekeep-signing-probe").decode()
    r = httpx.post(
        f"{OPENBAO}/v1/transit/sign/{KEY}",
        headers=HEADERS,
        json={
            "input": payload,
            "signature_algorithm": "pkcs1v15",
            "hash_algorithm": "sha2-256",
        },
        timeout=10,
    )
    assert r.status_code == 200, f"Signing failed: {r.status_code} {r.text[:200]}"

    signature = r.json()["data"]["signature"]
    # OpenBao returns `vault:v<n>:<standard-base64>`. A JWT needs the raw
    # signature in base64url with no padding, so the token service has to strip
    # the prefix and re-encode. Noted here because it is a twenty-minute
    # surprise otherwise, and the version number is what `kid` is derived from.
    assert signature.startswith("vault:v"), f"Unexpected signature format: {signature[:24]}"
    assert signature.split(":")[1] == f"v{key['latest_version']}"
