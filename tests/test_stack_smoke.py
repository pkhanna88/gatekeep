"""
Day 1 acceptance test.

The Day 1 bar is: `docker compose up` gives every engineer an identical
working stack. This is that sentence, written as a test.

Design rule for this file: one broken thing produces ONE failure. Tests that
depend on something already proven broken skip instead of piling on. Four red
lines for one cause wastes the reader's morning.

    make dev
    make smoke
"""

import socket

import httpx
import pytest

KEYCLOAK = "http://localhost:8080"
OPENFGA = "http://localhost:8081"
OPENBAO = "http://localhost:8200"

EXPECTED_USERS = {"priya@acme.test", "admin@acme.test", "auditor@acme.test"}

REALM_MISSING_HELP = """
The 'gatekeep' realm does not exist. Keycloak is running fine and is simply
empty, which is why the health check passed.

Almost always this means docker-compose.yml was told to mount a realm file
that was not there, so Docker created an empty FOLDER at that path instead.

Check both of these:

    ls -l deploy/keycloak-realm.json
        must be a FILE, not a directory

    docker compose exec keycloak ls -l /opt/keycloak/data/import/
        must list realm.json as a FILE, not a directory

If either is a directory, delete it, put the real file in place, then:

    docker compose down        # NOT restart - Keycloak only imports a realm
    docker compose up -d       # into a fresh database

To see what Keycloak thought it was doing:

    docker compose logs keycloak | grep -i -e import -e realm
"""


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def realm() -> str:
    """Confirms the realm exists. Everything Keycloak-related depends on this.

    Skips rather than fails, so the one real failure stays readable.
    """
    try:
        r = httpx.get(f"{KEYCLOAK}/realms/gatekeep/.well-known/openid-configuration", timeout=10)
    except httpx.ConnectError:
        pytest.skip("Keycloak is not reachable at all")
    if r.status_code != 200:
        pytest.skip("gatekeep realm missing - see test_keycloak_realm_imported")
    return "gatekeep"


@pytest.fixture(scope="session")
def admin_token(realm: str) -> str:
    r = httpx.post(
        f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
        timeout=10,
    )
    if r.status_code != 200:
        pytest.fail(
            f"Could not log into Keycloak as admin (HTTP {r.status_code}). "
            f"Check KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD in "
            f"docker-compose.yml. Response: {r.text[:200]}"
        )
    return r.json()["access_token"]


def _admin_get(path: str, token: str, **params) -> list:
    """Call the Keycloak admin API and fail readably instead of exploding.

    The admin API returns a JSON object on error, not a list, so indexing the
    result without checking gives a TypeError that hides the real problem.
    """
    r = httpx.get(
        f"{KEYCLOAK}/admin/realms/gatekeep/{path}",
        headers={"Authorization": f"Bearer {token}"},
        params=params or None,
        timeout=10,
    )
    if r.status_code == 404:
        pytest.fail(REALM_MISSING_HELP)
    if r.status_code != 200:
        pytest.fail(f"Keycloak admin API {path} returned {r.status_code}: {r.text[:200]}")
    body = r.json()
    if not isinstance(body, list):
        pytest.fail(f"Expected a list from {path}, got: {str(body)[:200]}")
    return body


# --- infrastructure is listening -------------------------------------------


def test_postgres_is_listening():
    assert _port_open("localhost", 5432), (
        "Postgres is not answering on 5432. Run `docker compose ps`. If another "
        "Postgres already owns the port, change the left-hand number in "
        "docker-compose.yml to 5433:5432."
    )


def test_redis_is_listening():
    assert _port_open("localhost", 6379), "Redis is not answering on 6379."


def test_openfga_is_answering():
    assert (
        httpx.get(f"{OPENFGA}/stores", timeout=10).status_code == 200
    ), "OpenFGA is not answering on 8081."


def test_openbao_is_unsealed():
    r = httpx.get(f"{OPENBAO}/v1/sys/health", timeout=10)
    assert r.status_code == 200, "OpenBao is not answering on 8200."
    assert r.json()["sealed"] is False, "OpenBao is sealed; it cannot sign anything."


# --- Keycloak is not just up, but actually configured ----------------------


def test_keycloak_realm_imported():
    """Keycloak starts happily with no realm at all, so 'the container is up'
    proves nothing. This is the test that catches an empty Keycloak."""
    try:
        r = httpx.get(f"{KEYCLOAK}/realms/gatekeep/.well-known/openid-configuration", timeout=10)
    except httpx.ConnectError:
        pytest.fail(
            f"Nothing is answering at {KEYCLOAK}. Keycloak is not running, or is "
            f"still starting. Check `docker compose ps` - a cold start takes 30-60s."
        )
    assert r.status_code == 200, REALM_MISSING_HELP
    assert r.json()["issuer"] == f"{KEYCLOAK}/realms/gatekeep", (
        "The realm exists but reports a different issuer than we expect. "
        "Everything must agree on one hostname - see the README."
    )


def test_keycloak_has_the_three_seeded_users(admin_token):
    """Day 1 asks for three specific users. Prove they are there."""
    found = {u["username"] for u in _admin_get("users", admin_token)}
    assert EXPECTED_USERS <= found, f"Missing users: {EXPECTED_USERS - found}"


def test_keycloak_console_client_uses_pkce(admin_token):
    """A browser app cannot keep a secret, so it must use PKCE (section 3.3).

    Called out as a common and serious mistake, so it gets a test rather than
    relying on someone noticing it in review.
    """
    clients = _admin_get("clients", admin_token, clientId="gatekeep-console")
    assert clients, "The gatekeep-console client is missing from the realm."
    console = clients[0]
    assert console["publicClient"] is True, (
        "gatekeep-console is registered as confidential. A browser app cannot "
        "keep a secret and must be public."
    )
    assert (
        console["attributes"].get("pkce.code.challenge.method") == "S256"
    ), "gatekeep-console is a public client without PKCE enabled."
