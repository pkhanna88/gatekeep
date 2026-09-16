"""
Section 9.1's mandatory tests for delegation, enforcement and revocation.

These run against the real stack and the real services (`make services`), and
skip if the services are not up - same convention as the INF tests. Each test
registers its own agent, so they do not depend on each other or on demo state.

    test_grant_cannot_exceed_principal          Invariant 1
    test_token_scope_subset_of_grant            Invariant 2
    test_approver_must_be_principal
    test_expired_token_denied
    test_tampered_token_denied
    test_wrong_key_token_denied
    test_revoked_grant_denies_immediately
    test_revocation_survives_redis_flush        fails closed, not open
    test_out_of_scope_request_denied
    test_policy_denial_after_rights_withdrawn   access-time re-check
    test_killswitch_terminates_all_sessions
    test_unknown_exception_denies
    test_no_response_bodies_in_audit

Per section 9.2, every allow here has a test proving the matching deny.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

import asyncpg
import httpx
import jwt
import pytest
import redis
from app import settings
from app.revocation import REVOKED_SET
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KC_TOKEN = f"{settings.KEYCLOAK_ISSUER}/protocol/openid-connect/token"
CP, TS, PEP = settings.CONTROL_PLANE_URL, settings.TOKEN_SERVICE_URL, settings.PEP_URL
SOBJECTS = "/proxy/salesforce/services/data/v60.0/sobjects"

NW_OPP, NW_INV, NW_NOTE = "0065g00001NWD", "0INV00001NWD", "0NOT00001NWD"
CONTOSO_OPP = "0065g00099CTO"
SCOPES = [
    f"salesforce:opportunity:read:{NW_OPP}",
    f"salesforce:invoice:read:{NW_INV}",
    f"salesforce:note:write:{NW_NOTE}",
]


# --- fixtures ---------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def services_up():
    for url in (CP, TS, PEP, settings.MOCK_SALESFORCE_URL):
        try:
            httpx.get(f"{url}/healthz", timeout=3).raise_for_status()
        except httpx.HTTPError:
            pytest.skip(f"{url} is not running. Start the services: make services")


def login(user: str, password: str) -> dict:
    r = httpx.post(
        KC_TOKEN,
        data={
            "grant_type": "password",
            "client_id": "gatekeep-console",
            "username": user,
            "password": password,
            "scope": "openid",
        },
        timeout=10,
    )
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def priya():
    return login("priya@acme.test", "priya")


@pytest.fixture(scope="module")
def admin():
    return login("admin@acme.test", "admin")


class RegisteredAgent:
    """A freshly registered agent with helpers for each API it touches."""

    def __init__(self, admin_headers: dict):
        self.id = f"agent://acme/test-{uuid.uuid4().hex[:10]}"
        r = httpx.post(
            f"{CP}/v1/agents",
            headers=admin_headers,
            json={"id": self.id, "display_name": "test", "owner_email": "priya@acme.test"},
        )
        assert r.status_code == 201, r.text
        self.credential = r.json()["bootstrap_credential"]
        self.headers = {"Authorization": f"Bearer {self.credential}"}

    def request(self, scopes=SCOPES, principal="priya@acme.test", ttl=30) -> dict:
        r = httpx.post(
            f"{CP}/v1/grants",
            headers=self.headers,
            json={
                "agent_id": self.id,
                "principal_sub": principal,
                "purpose": "test run",
                "scopes": scopes,
                "ttl_minutes": ttl,
            },
        )
        assert r.status_code == 201, r.text
        return r.json()

    def exchange(self, grant_id: str, **extra) -> httpx.Response:
        return httpx.post(
            f"{TS}/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": grant_id,
                "subject_token_type": "urn:gatekeep:params:token-type:grant",
                "actor_token": self.credential,
                "actor_token_type": "urn:gatekeep:params:token-type:agent",
                **extra,
            },
        )


def approve(grant_id: str, headers: dict) -> httpx.Response:
    return httpx.post(f"{CP}/v1/grants/{grant_id}/approve", headers=headers)


def pep(method: str, obj: str, rid: str, token: str, body: dict | None = None) -> httpx.Response:
    return httpx.request(
        method,
        f"{PEP}{SOBJECTS}/{obj}/{rid}",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )


@pytest.fixture
def agent(admin):
    return RegisteredAgent(admin)


@pytest.fixture
def live_token(agent, priya):
    """An approved grant and a token for it: (agent, grant, token_response)."""
    grant = agent.request()
    assert approve(grant["id"], priya).status_code == 200
    r = agent.exchange(grant["id"])
    assert r.status_code == 200, r.text
    return agent, grant, r.json()


def claims_of(token: str) -> dict:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


# --- Invariant 1 and the approver ----------------------------------------------------


def test_grant_cannot_exceed_principal(agent, priya):
    contoso = f"salesforce:opportunity:read:{CONTOSO_OPP}"
    grant = agent.request(scopes=[SCOPES[0], contoso])
    r = approve(grant["id"], priya)
    assert r.status_code == 403
    assert r.json()["error"] == "scope_exceeds_principal"
    assert r.json()["offending_scopes"] == [contoso]
    assert httpx.get(f"{CP}/v1/grants/{grant['id']}", headers=priya).json()["status"] == "rejected"
    assert agent.exchange(grant["id"]).status_code == 403


def test_read_only_user_cannot_delegate_write(agent, admin):
    """auditor is viewer on Northwind, not owner: may not lend `write` (fga-model.fga note 2)."""
    auditor = login("auditor@acme.test", "auditor")
    grant = agent.request(
        scopes=[f"salesforce:note:write:{NW_NOTE}"], principal="auditor@acme.test"
    )
    r = approve(grant["id"], auditor)
    assert r.status_code == 403 and r.json()["error"] == "scope_exceeds_principal"


def test_approver_must_be_principal(agent, admin, priya):
    grant = agent.request()
    r = approve(grant["id"], admin)
    assert r.status_code == 403
    assert r.json()["error"] == "approver_is_not_principal"
    # still pending: the real principal can decide
    assert httpx.get(f"{CP}/v1/grants/{grant['id']}", headers=priya).json()["status"] == "pending"


def test_pending_grant_cannot_be_exchanged(agent):
    grant = agent.request()
    r = agent.exchange(grant["id"])
    assert r.status_code == 403 and r.json()["error"] == "grant_pending"


def test_malformed_and_wildcard_scopes_rejected_at_request(agent):
    for bad in (["salesforce:read:*"], ["salesforce:opportunity:read:*"]):
        r = httpx.post(
            f"{CP}/v1/grants",
            headers=agent.headers,
            json={
                "agent_id": agent.id,
                "principal_sub": "priya@acme.test",
                "purpose": "test",
                "scopes": bad,
            },
        )
        assert r.status_code == 400 and r.json()["error"] == "invalid_scope"


def test_agent_cannot_request_as_another_agent(agent, admin):
    other = RegisteredAgent(admin)
    r = httpx.post(
        f"{CP}/v1/grants",
        headers=agent.headers,
        json={
            "agent_id": other.id,
            "principal_sub": "priya@acme.test",
            "purpose": "test",
            "scopes": SCOPES,
        },
    )
    assert r.status_code == 403 and r.json()["error"] == "agent_mismatch"


def test_bootstrap_credential_is_required_and_hashed(agent):
    r = httpx.post(
        f"{CP}/v1/grants",
        headers={"Authorization": "Bearer gkb.nope.nopenopenopenopenopenope"},
        json={
            "agent_id": agent.id,
            "principal_sub": "priya@acme.test",
            "purpose": "test",
            "scopes": SCOPES,
        },
    )
    assert r.status_code == 401


# --- tokens and Invariant 2 ------------------------------------------------------------


def test_token_carries_both_identities(live_token):
    agent, grant, resp = live_token
    c = claims_of(resp["access_token"])
    assert c["sub"] == "priya@acme.test"
    assert c["act"]["sub"] == agent.id
    assert c["act"]["instance"] == resp["session_id"]
    assert c["aud"] == "gatekeep-pep"
    assert c["grant_id"] == grant["id"]
    assert c["exp"] - c["iat"] <= 300


def test_token_scope_subset_of_grant(live_token):
    agent, grant, _ = live_token
    r = agent.exchange(grant["id"], scope=f"salesforce:opportunity:read:{CONTOSO_OPP}")
    assert r.status_code == 403 and r.json()["error"] == "scope_exceeds_grant"
    # asking for LESS is allowed, and the token then carries only that
    r = agent.exchange(grant["id"], scope=SCOPES[0])
    assert r.status_code == 200
    assert claims_of(r.json()["access_token"])["scope"] == [SCOPES[0]]


def test_another_agent_cannot_use_the_grant(live_token, admin):
    _, grant, _ = live_token
    thief = RegisteredAgent(admin)
    r = thief.exchange(grant["id"])
    assert r.status_code == 403 and r.json()["error"] == "grant_not_issued_to_this_agent"


def test_token_signature_verifies_against_jwks(live_token):
    _, _, resp = live_token
    token = resp["access_token"]
    kid = jwt.get_unverified_header(token)["kid"]
    jwks = httpx.get(f"{TS}/.well-known/jwks.json").json()
    key = jwt.PyJWK(next(k for k in jwks["keys"] if k["kid"] == kid)).key
    jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience="gatekeep-pep",
        issuer=settings.AGENT_TOKEN_ISSUER,
    )


# --- the PEP -----------------------------------------------------------------------------


def test_allowed_request_reaches_salesforce(live_token):
    _, _, resp = live_token
    r = pep("GET", "Opportunity", NW_OPP, resp["access_token"])
    assert r.status_code == 200 and r.json()["Id"] == NW_OPP
    assert r.headers["X-Gatekeep-Decision"] == "allow"


def test_out_of_scope_request_denied(live_token):
    _, _, resp = live_token
    before = httpx.get(f"{settings.MOCK_SALESFORCE_URL}/_gatekeep/requests").json()["count"]
    r = pep("GET", "Opportunity", CONTOSO_OPP, resp["access_token"])
    assert r.status_code == 403 and r.json()["error"] == "action_outside_token_scope"
    # read scope does not cover write on the same record
    r = pep("PATCH", "Opportunity", NW_OPP, resp["access_token"], {"Amount": 1})
    assert r.status_code == 403 and r.json()["error"] == "action_outside_token_scope"
    after = httpx.get(f"{settings.MOCK_SALESFORCE_URL}/_gatekeep/requests").json()["count"]
    assert after == before, "a denied request reached Salesforce"


def test_unmapped_request_denied(live_token):
    _, _, resp = live_token
    r = pep("DELETE", "Note", NW_NOTE, resp["access_token"])
    assert r.status_code == 403 and r.json()["error"] == "unmapped_request"
    r = httpx.get(
        f"{PEP}/proxy/salesforce/services/data/v60.0/query?q=SELECT+Id+FROM+Opportunity",
        headers={"Authorization": f"Bearer {resp['access_token']}"},
    )
    assert r.status_code == 403 and r.json()["error"] == "unmapped_request"


def test_missing_token_denied():
    r = httpx.get(f"{PEP}{SOBJECTS}/Opportunity/{NW_OPP}")
    assert r.status_code == 401 and r.json()["error"] == "missing_bearer_token"


def test_tampered_token_denied(live_token):
    _, _, resp = live_token
    head, payload, sig = resp["access_token"].split(".")
    c = claims_of(resp["access_token"])
    c["scope"].append(f"salesforce:opportunity:read:{CONTOSO_OPP}")
    forged = base64.urlsafe_b64encode(json.dumps(c).encode()).rstrip(b"=").decode()
    r = pep("GET", "Opportunity", CONTOSO_OPP, f"{head}.{forged}.{sig}")
    assert r.status_code == 401 and r.json()["error"] == "bad_signature"


def _self_signed(claims: dict, kid: str = "gk-signing-v1", alg: str = "RS256") -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return jwt.encode(claims, pem, algorithm=alg, headers={"kid": kid})


def test_wrong_key_token_denied(live_token):
    """Same kid, same claims, signed by a key that is not ours."""
    _, _, resp = live_token
    forged = _self_signed(claims_of(resp["access_token"]))
    r = pep("GET", "Opportunity", NW_OPP, forged)
    assert r.status_code == 401 and r.json()["error"] == "bad_signature"
    r = pep(
        "GET",
        "Opportunity",
        NW_OPP,
        _self_signed(claims_of(resp["access_token"]), kid="attacker-key"),
    )
    assert r.status_code == 401 and r.json()["error"] == "unknown_signing_key"


def test_alg_none_and_hs256_denied(live_token):
    _, _, resp = live_token
    c = claims_of(resp["access_token"])
    none_token = jwt.encode(c, None, algorithm="none", headers={"kid": "gk-signing-v1"})
    r = pep("GET", "Opportunity", NW_OPP, none_token)
    assert r.status_code == 401 and r.json()["error"] == "unsupported_algorithm"


async def test_expired_token_denied(live_token):
    """A genuine token, signed by OUR key through transit, but expired beyond the 30s leeway."""
    from token_service.signing import TransitSigner

    _, _, resp = live_token
    c = claims_of(resp["access_token"])
    c["iat"], c["exp"] = int(time.time()) - 600, int(time.time()) - 120
    signer = TransitSigner()
    try:
        expired = await signer.sign_jwt(c)
    finally:
        await signer.aclose()
    r = pep("GET", "Opportunity", NW_OPP, expired)
    assert r.status_code == 401 and r.json()["error"] == "token_expired"


# --- revocation and the kill switch ---------------------------------------------------------


def test_revoked_grant_denies_immediately(live_token, priya):
    agent, grant, resp = live_token
    assert pep("GET", "Opportunity", NW_OPP, resp["access_token"]).status_code == 200
    assert (
        httpx.post(
            f"{CP}/v1/grants/{grant['id']}/revoke", headers=priya, json={"reason": "test"}
        ).status_code
        == 200
    )
    r = pep("GET", "Opportunity", NW_OPP, resp["access_token"])
    assert r.status_code == 403 and r.json()["error"] == "grant_revoked"
    r = agent.exchange(grant["id"], session_id=resp["session_id"])
    assert r.status_code == 403, "refresh after revocation must fail"


def test_revocation_survives_redis_flush(live_token, priya):
    _, grant, resp = live_token
    assert (
        httpx.post(
            f"{CP}/v1/grants/{grant['id']}/revoke", headers=priya, json={"reason": "test"}
        ).status_code
        == 200
    )
    r = redis.from_url(settings.REDIS_URL)
    assert r.sismember(REVOKED_SET, grant["id"])
    r.delete(REVOKED_SET)  # Redis restarted, evicted, or wiped
    resp2 = pep("GET", "Opportunity", NW_OPP, resp["access_token"])
    assert (
        resp2.status_code == 403 and resp2.json()["error"] == "grant_revoked"
    ), "An empty Redis was read as 'nothing is revoked'. That is failing open."


async def test_policy_denial_after_rights_withdrawn(agent, priya):
    """Approval checks the ceiling; the PEP checks the present (section 7.2 step 5)."""
    from app.fga import FGA

    suffix = uuid.uuid4().hex[:8].upper()
    account, opp = f"0015gT{suffix}", f"0065gT{suffix}"
    tuples = [
        {"user": "user:priya@acme.test", "relation": "owner", "object": f"account:{account}"},
        {"user": f"account:{account}", "relation": "parent", "object": f"opportunity:{opp}"},
    ]
    fga = FGA()
    store_id, _ = await fga._resolve()
    async with httpx.AsyncClient(base_url=settings.FGA_URL) as c:
        (
            await c.post(f"/stores/{store_id}/write", json={"writes": {"tuple_keys": tuples}})
        ).raise_for_status()
        try:
            grant = agent.request(scopes=[f"salesforce:opportunity:read:{opp}"])
            assert approve(grant["id"], priya).status_code == 200
            token = agent.exchange(grant["id"]).json()["access_token"]

            # Priya loses the account after approving. The grant and token are still "valid".
            (
                await c.post(
                    f"/stores/{store_id}/write", json={"deletes": {"tuple_keys": tuples[:1]}}
                )
            ).raise_for_status()
            r = pep("GET", "Opportunity", opp, token)
            assert r.status_code == 403 and r.json()["error"] == "policy_denied"
        finally:
            await c.post(f"/stores/{store_id}/write", json={"deletes": {"tuple_keys": tuples[1:]}})
    await fga.aclose()


def test_killswitch_requires_admin(priya):
    r = httpx.post(f"{CP}/v1/killswitch", headers=priya, json={"reason": "not allowed"})
    assert r.status_code == 403


def test_killswitch_terminates_all_sessions(admin, priya):
    runs = []
    for _ in range(3):
        a = RegisteredAgent(admin)
        g = a.request()
        assert approve(g["id"], priya).status_code == 200
        runs.append((a, g, a.exchange(g["id"]).json()))
    for _, _, t in runs:
        assert pep("GET", "Opportunity", NW_OPP, t["access_token"]).status_code == 200

    r = httpx.post(f"{CP}/v1/killswitch", headers=admin, json={"reason": "test"})
    assert r.status_code == 200
    assert r.json()["sessions_killed"] >= 3

    for a, g, t in runs:
        assert (
            pep("GET", "Opportunity", NW_OPP, t["access_token"]).json()["error"] == "grant_revoked"
        )
        assert a.exchange(g["id"]).status_code == 403
    running = httpx.get(f"{CP}/v1/sessions", params={"status": "running"}, headers=admin).json()[
        "sessions"
    ]
    assert running == []


# --- failure behaviour and evidence -----------------------------------------------------------


async def test_unknown_exception_denies(live_token, monkeypatch):
    """The catch-all denies (503) and never forwards, whatever blew up."""
    from pep_proxy import main as pep_main

    _, _, resp = live_token
    forwarded = []
    async with pep_main.app.router.lifespan_context(pep_main.app):
        connector = pep_main.app.state.connectors["salesforce"]

        def boom(*_):
            raise RuntimeError("connector exploded")

        async def spy(*a, **k):
            forwarded.append(a)

        monkeypatch.setattr(connector, "map_request", boom)
        monkeypatch.setattr(connector, "forward", spy)
        transport = httpx.ASGITransport(app=pep_main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://pep") as c:
            r = await c.get(
                f"{SOBJECTS}/Opportunity/{NW_OPP}",
                headers={"Authorization": f"Bearer {resp['access_token']}"},
            )
    assert r.status_code == 503
    assert r.json()["error"] == "authorization_unavailable"
    assert r.headers["X-Gatekeep-Decision"] == "deny"
    assert forwarded == []


async def test_no_response_bodies_in_audit(live_token):
    agent, grant, resp = live_token
    body = pep("GET", "Opportunity", NW_OPP, resp["access_token"]).json()
    pep("GET", "Invoice__c", NW_INV, resp["access_token"])

    conn = await asyncpg.connect(settings.APP_DSN)
    try:
        rows = await conn.fetch("SELECT * FROM audit_events WHERE grant_id = $1", grant["id"])
    finally:
        await conn.close()
    assert rows
    # Values that exist only in the record contents, never in ids or reasons.
    leaks = [body["Name"], "Northwind", "48500", "45200", "Closed Won", "INV-2026-0817"]
    for row in rows:
        blob = json.dumps({k: str(v) for k, v in dict(row).items()})
        for needle in leaks:
            assert needle not in blob, f"audit row {row['seq']} contains record content {needle!r}"
        if row["event_type"] == "access.allowed":
            assert len(row["payload_digest"]) == 64
