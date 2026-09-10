"""
What the realm promises the other three roles.

test_stack_smoke.py answers "is my machine working". This file answers a
different question: does the realm actually issue the claims the rest of the
system is being written against? Those are separable failures. Keycloak can be
perfectly healthy, import cleanly, and still hand out a token that no service
can use, which is what it was doing until Day 7.

Two defects are pinned here so they cannot come back:

  The principal identifier. Keycloak's `sub` is an opaque UUID
  (4ce26fd3-6587-...). Every OpenFGA tuple, grants.principal_sub, and the §6.3
  agent token are written in terms of an email address. §7.1 compares
  approver_claims["sub"] against grant.principal_sub, and as shipped those two
  could never match - Invariant 1 would have failed closed for the right reason
  by accident, and read like a policy bug rather than a realm bug.

  We did not paper over it by forcing `sub` to the email. OIDC wants `sub`
  opaque and stable, and §3.3 sells "swap Keycloak for Okta or Entra and it is
  configuration, not code" - a promise that breaks the moment we depend on
  another IdP's `sub` being an email. Instead the realm mints an explicit
  `principal` claim. Swapping IdP means remapping one claim. See
  docs/DECISIONS.md, Day 7.

  The audience. §4.4 lists audience as something we verify at the Human ->
  Console boundary, and tokens were arriving with no `aud` at all. BE1 cannot
  write the Day 4 approval gate against a claim that is not there.
"""

import httpx
import pytest

KEYCLOAK = "http://localhost:8080"
REALM = "gatekeep"
CONSOLE_CLIENT = "gatekeep-console"
CONTROL_PLANE_CLIENT = "gatekeep-control-plane"

# username -> (password, expected realm role)
SEEDED_USERS = {
    "priya@acme.test": ("priya", "analyst"),
    "admin@acme.test": ("admin", "security-admin"),
    "auditor@acme.test": ("auditor", "auditor"),
}


def _decode(token: str) -> dict:
    """Read a JWT payload without verifying it.

    Legitimate here and nowhere near a service path: this file is asserting what
    the IdP puts in the token, not deciding anything. CI greps services/, tools/
    and sdk/ for unverified decoding; tests/ is deliberately outside that grep.
    """
    import base64
    import json

    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


@pytest.fixture(scope="session")
def realm_up() -> None:
    try:
        r = httpx.get(f"{KEYCLOAK}/realms/{REALM}/.well-known/openid-configuration", timeout=10)
    except httpx.ConnectError:
        pytest.skip("Keycloak is not reachable at all")
    if r.status_code != 200:
        pytest.skip("gatekeep realm missing - see test_keycloak_realm_imported")


def _user_token(username: str, password: str) -> str:
    r = httpx.post(
        f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CONSOLE_CLIENT,
            "username": username,
            "password": password,
            "scope": "openid",
        },
        timeout=10,
    )
    if r.status_code != 200:
        pytest.fail(
            f"Could not get a token for {username} (HTTP {r.status_code}). "
            f"Response: {r.text[:200]}"
        )
    return r.json()["access_token"]


@pytest.fixture(scope="session")
def priya_claims(realm_up) -> dict:
    return _decode(_user_token("priya@acme.test", "priya"))


# --- the principal identifier ----------------------------------------------


@pytest.mark.parametrize("username", sorted(SEEDED_USERS))
def test_token_carries_a_principal_claim(realm_up, username):
    """The claim the rest of Gatekeep keys off. Without it there is no join
    between a Keycloak login and an OpenFGA tuple."""
    password, _ = SEEDED_USERS[username]
    claims = _decode(_user_token(username, password))
    assert "principal" in claims, (
        "Token has no `principal` claim. deploy/keycloak-realm.json should map "
        "one onto gatekeep-console via oidc-usermodel-property-mapper. Note that "
        "Keycloak only imports a realm into a FRESH database - after editing the "
        "realm file you need `make clean && make dev`, not `docker compose restart`."
    )
    assert claims["principal"] == username, (
        f"principal is {claims['principal']!r}, expected {username!r}. "
        f"The seed tuples in deploy/seed/fga-tuples.json are written as "
        f"user:{username}, so a mismatch here means every policy check misses."
    )


def test_principal_is_not_the_opaque_sub(priya_claims):
    """Documents why `principal` exists at all.

    If this ever fails because sub == principal, someone has forced the email
    into `sub`. That works locally and breaks the IdP-portability claim in §3.3
    the first time a customer points us at Okta.
    """
    if "principal" not in priya_claims:
        pytest.fail("No `principal` claim - see test_token_carries_a_principal_claim")
    assert priya_claims["sub"] != priya_claims["principal"], (
        "sub now equals principal, which means sub has been overridden to the "
        "email. Prefer keeping sub opaque and mapping `principal` explicitly - "
        "see docs/DECISIONS.md, Day 7."
    )
    assert len(priya_claims["sub"]) >= 32, "sub is not the opaque identifier we expect"


# --- the audience ----------------------------------------------------------


def test_token_carries_a_verifiable_audience(priya_claims):
    """§4.4 verifies audience at the Human -> Console boundary. A token minted
    for one service must not be replayable at another (§11, Audience)."""
    aud = priya_claims.get("aud")
    assert aud is not None, (
        "Token has no `aud` claim, so the control plane has nothing to verify at "
        "the Human -> Console trust boundary. Add an oidc-audience-mapper to "
        "gatekeep-console in deploy/keycloak-realm.json."
    )
    audiences = [aud] if isinstance(aud, str) else list(aud)
    assert CONTROL_PLANE_CLIENT in audiences, (
        f"aud is {audiences}, which does not include {CONTROL_PLANE_CLIENT}. "
        f"That is the API the console presents this token to."
    )


def test_token_ttl_is_five_minutes(priya_claims):
    """§2.10. Also the number a customer's security architect will ask for."""
    assert priya_claims["exp"] - priya_claims["iat"] == 300


# --- roles, which Day 16 gates the kill switch on --------------------------


@pytest.mark.parametrize("username", sorted(SEEDED_USERS))
def test_user_carries_exactly_its_seeded_role(realm_up, username):
    """Day 16 needs `security-admin` to gate POST /v1/killswitch, and needs a
    test that a non-admin is refused. The endpoint is BE1's; this is the half
    that has to be true first - that the role reaches the token at all, and that
    it does not reach the wrong people."""
    password, expected_role = SEEDED_USERS[username]
    claims = _decode(_user_token(username, password))
    roles = set((claims.get("realm_access") or {}).get("roles", []))

    assert expected_role in roles, f"{username} is missing the {expected_role!r} realm role"

    others = {r for _, r in SEEDED_USERS.values()} - {expected_role}
    leaked = roles & others
    assert not leaked, (
        f"{username} carries {leaked}, which belongs to another user. "
        f"Kill-switch gating is only as good as this separation."
    )


# --- client registration ---------------------------------------------------


def test_control_plane_is_a_confidential_client(realm_up):
    """§3.3: a backend service can hold a secret and must be confidential.
    Getting public vs confidential wrong is called out as a common and serious
    mistake, so it gets a test rather than a code review."""
    r = httpx.post(
        f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": CONTROL_PLANE_CLIENT,
            "client_secret": "dev-control-plane-secret-not-for-production",
        },
        timeout=10,
    )
    assert r.status_code == 200, (
        f"gatekeep-control-plane could not authenticate with its client secret "
        f"(HTTP {r.status_code}): {r.text[:200]}. BE1 needs this to call Keycloak "
        f"as a service."
    )


def test_control_plane_cannot_authenticate_without_its_secret(realm_up):
    """The deny half. A confidential client that accepts an empty secret is a
    public client wearing a costume."""
    r = httpx.post(
        f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "client_credentials", "client_id": CONTROL_PLANE_CLIENT},
        timeout=10,
    )
    assert r.status_code == 401, (
        f"Expected 401 without a client secret, got {r.status_code}. "
        f"gatekeep-control-plane may have been registered as a public client."
    )
