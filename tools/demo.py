"""
The Gatekeep demo - section 10.1's narrative, end to end, against the real stack.

    make demo                 full run, every step explained
    make demo PAUSE=1         stop between steps (for presenting)
    make demo BRIEF=1         results only, no explanations (the timed run, and CI)

There is no web console yet, so each step says, in two registers:

    WHAT IS HAPPENING   plain English - what a business person would see
    UNDER THE HOOD      the services, endpoints and checks involved

and then shows the real HTTP calls and what came back. Nothing is simulated:
the agent's requests go through the real token service and PEP, Priya logs in
via Keycloak, policy comes from OpenFGA, keys stay in OpenBao, and the audit
chain is the real table. Every expected outcome is asserted; the script exits
non-zero if anything misbehaves, so it cannot quietly turn into a slideshow.

Needs:  make dev && make migrate && make seed, and `make services` running.
It resets demo state first (make demo-reset) unless --no-reset.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import subprocess
import sys
import time

import asyncpg
import httpx
import jwt
from agent import AGENT_ID, INVOICE, NOTE, OPPORTUNITY, PRINCIPAL, SCOPES, Agent, register
from gklib import (
    audit_table,
    bearer,
    bold,
    cyan,
    decode_unverified,
    dim,
    grant_card,
    green,
    human_token,
    red,
    settings,
    show_http,
    token_explained,
    wrap,
    yellow,
)

OWNER_DSN = "postgres://gatekeep:gatekeep@localhost:5432/gatekeep"
CONTOSO_OPPORTUNITY = "0065g00099CTO"

PAUSE = False
BRIEF = False
failures: list[str] = []


# --- presentation ---------------------------------------------------------------


def step(n: int, title: str) -> None:
    if PAUSE:
        input(dim("\n    [enter for next step]"))
    print("\n" + bold("=" * 78))
    print(bold(f"  STEP {n}.  {title}"))
    print(bold("=" * 78))


def plain(text: str) -> None:
    if BRIEF:
        return
    print("\n" + yellow("  WHAT IS HAPPENING"))
    print(wrap(text, 4))


def technical(text: str) -> None:
    if BRIEF:
        return
    print("\n" + cyan("  UNDER THE HOOD"))
    print(wrap(text, 4))


def live() -> None:
    print("\n" + dim("  --- live ---"))


def check(ok: bool, msg: str) -> bool:
    if not ok:
        failures.append(msg)
        print(red(f"  UNEXPECTED: {msg}"))
    return ok


def outcome(ok: bool, text: str) -> None:
    print(("  " + green("OK   ") if ok else "  " + red("FAIL ")) + text)


def refused(r: httpx.Response, expected_error: str, expected_status: int = 403) -> dict:
    body = r.json()
    check(r.status_code == expected_status, f"expected HTTP {expected_status}, got {r.status_code}")
    check(
        body.get("error") == expected_error, f"expected {expected_error}, got {body.get('error')}"
    )
    print(f"  {red('REFUSED')}  HTTP {r.status_code}  {bold(body.get('error', '?'))}")
    print(f"           {body.get('message')}")
    return body


def arrivals() -> int:
    return httpx.get(f"{settings.MOCK_SALESFORCE_URL}/_gatekeep/requests", timeout=5).json()[
        "count"
    ]


# --- the story ------------------------------------------------------------------


def step_1_the_problem() -> None:
    step(1, "The problem")
    plain("""
        Priya is a finance analyst at Acme. She wants an AI agent to reconcile
        August invoices for one customer, Northwind Traders.

        Today she has two options, and security rejects both. Give the agent a
        service account - a master key to all of Salesforce that never expires
        and logs everything as "svc-agent". Or give it her own login - then
        everything it does looks like Priya did it, and nobody can tell the
        human from the machine.

        Gatekeep is the third option: Priya lends the agent a small, specific,
        short-lived slice of her own access, and every use of it is provable.
    """)
    technical("""
        Services in play: Keycloak (humans log in, :8080), OpenFGA (who may
        touch which record, :8081), OpenBao (holds the token-signing key,
        :8200), Postgres (grants and the audit chain), Redis (fast revocation),
        and ours: control plane :8000, token service :8001, PEP proxy :8002,
        and a mock Salesforce :8003 that only answers the PEP.
    """)


def step_2_the_cast() -> dict[str, str]:
    step(2, "Who is who")
    plain("""
        Three people log in through the company's normal login system. Gatekeep
        never sees a password. Priya owns the Northwind account. The security
        admin can use the kill switch but, deliberately, has no access to
        customer data. The auditor can read the evidence.
    """)
    technical("""
        OIDC password grant against the `gatekeep` realm (the browser console
        would use authorization code + PKCE; the resulting token is the same).
        The control plane verifies each token's RS256 signature against
        Keycloak's JWKS, the issuer, expiry, and aud=gatekeep-control-plane. It
        identifies people by the `principal` claim (their email), not `sub`,
        which is Keycloak's opaque UUID - so swapping Keycloak for Okta or Entra
        is a claim mapping, not a rewrite.
    """)
    live()
    tokens = {}
    for who in ("priya", "admin", "auditor"):
        tokens[who] = human_token(who)
        _, claims = decode_unverified(tokens[who])
        roles = [
            r
            for r in claims["realm_access"]["roles"]
            if r in ("analyst", "security-admin", "auditor")
        ]
        print(
            f"  {green(claims['principal']):<30} roles {roles}   "
            f"token lives {claims['exp'] - claims['iat']}s"
        )
    print()
    print(dim("  Policy facts in OpenFGA (deploy/seed/fga-tuples.json):"))
    print(dim("    priya@acme.test   owner   account:0015g00001XYZ  (Northwind Traders)"))
    print(
        dim(
            "    Northwind is parent of opportunity 0065g00001NWD, invoice 0INV00001NWD, "
            "note 0NOT00001NWD"
        )
    )
    print(dim("    account:0015g00099ABC (Contoso Ltd) - nobody holds anything on it"))
    return tokens


async def step_3_register(tokens) -> Agent:
    step(3, "The agent gets an identity")
    plain("""
        Before an agent can ask for anything it is registered, by a security
        admin, and given a secret password of its own. That password is shown
        once. Gatekeep keeps only a scrambled fingerprint of it, so even someone
        who steals the database cannot use it. The password proves WHO the agent
        is. It grants no access to anything.
    """)
    technical("""
        POST /v1/agents (security-admin role required). Credential format
        gkb.<key_id>.<secret>: key_id is a public lookup handle, secret is 32
        random bytes. Stored as an argon2id hash (memory-hard, salted). This is
        the weak link we state openly: a bootstrap credential, not SPIFFE
        workload attestation, which is Phase 2 (docs/SECURITY.md 8.1).
    """)
    live()
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/agents",
        headers=bearer(tokens["priya"]),
        json={"id": AGENT_ID, "display_name": "Invoice reconciler", "owner_email": PRINCIPAL},
        timeout=15,
    )
    print(dim("  Priya (an analyst) tries to register an agent:"))
    refused(r, "forbidden")
    print()
    credential = register(tokens["admin"])
    print(dim("  The admin registers it:"))
    show_http("POST", "/v1/agents", 201)
    print(f"  bootstrap credential  {bold(credential[:16])}{dim('... (shown once)')}")
    conn = await asyncpg.connect(OWNER_DSN)
    try:
        stored = await conn.fetchval("SELECT bootstrap_hash FROM agents WHERE id = $1", AGENT_ID)
    finally:
        await conn.close()
    print(f"  stored in Postgres    {dim(stored[:60] + '...')}")
    check(stored.startswith("$argon2id$"), "credential not argon2id-hashed")
    check(credential not in stored, "raw credential stored")
    return Agent(credential)


def step_4_request(agent: Agent, tokens) -> str:
    step(4, "The agent asks Priya for permission")
    plain("""
        The agent says: "I need to read this opportunity and this invoice on
        Northwind, and write one note, for 30 minutes, so I can reconcile August
        invoices." That request lands in Priya's approval queue. Until she says
        yes, the agent has nothing - if it tries to get a key now, it is refused.
    """)
    technical("""
        POST /v1/grants, authenticated with the agent's bootstrap credential.
        Scopes use system:resource_type:action:resource_id and are parsed
        strictly - unknown systems, types or actions, malformed ids and
        wildcards are rejected up front. The grant is stored `pending` with an
        absolute expires_at, and grant.requested is written to the audit chain.
    """)
    live()
    r = agent.request_grant()
    check(r.status_code == 201, f"grant request returned {r.status_code}")
    grant = r.json()
    show_http("POST", "/v1/grants", r.status_code)
    print()
    print(dim('  What Priya sees in her queue (make gk ARGS="pending --as priya"):\n'))
    r = httpx.get(
        f"{settings.CONTROL_PLANE_URL}/v1/grants/{grant['id']}", headers=bearer(tokens["priya"])
    )
    grant_card(r.json())
    print()
    print(dim("  The agent tries to get a token before approval:"))
    refused(agent.exchange(grant["id"]), "grant_pending")
    return grant["id"]


def step_5_wrong_approver(grant_id: str, tokens) -> None:
    step(5, "Someone else tries to approve it")
    plain("""
        The security admin is senior and could, in most systems, approve this
        for Priya. Gatekeep refuses. Only Priya can lend Priya's access. If an
        admin could approve on her behalf, the record would say Priya authorised
        something she never saw - exactly the accountability failure we exist
        to prevent. The attempt is logged.
    """)
    technical("""
        POST /v1/grants/{id}/approve checks approver principal == grant
        principal_sub before anything else (section 7.1). Refusal: 403
        approver_is_not_principal, audit grant.rejected with the reason. The
        grant stays pending so the real principal can still decide.
    """)
    live()
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/grants/{grant_id}/approve",
        headers=bearer(tokens["admin"]),
    )
    refused(r, "approver_is_not_principal")


def step_6_overreach(agent: Agent, tokens) -> None:
    step(6, "An agent asks for more than Priya herself has   (Invariant 1)")
    plain("""
        A second request slips in one extra record: an opportunity on Contoso,
        a customer Priya has no access to. Even if Priya clicks approve without
        reading carefully, Gatekeep checks every item against what Priya is
        actually allowed to see - and refuses the whole grant, naming the item
        she does not hold. You cannot lend what you do not have.
    """)
    technical("""
        Invariant 1. On approve, each scope becomes an OpenFGA check as the
        principal: read -> `viewer`, write -> `editor`, object = type:id.
        Priya is viewer of the Northwind opportunity only by inheritance
        (opportunity -> parent account -> owner). All failures are collected;
        any failure returns 403 scope_exceeds_principal with offending_scopes,
        marks the grant rejected, and audits the refusal. If OpenFGA cannot
        answer, approval fails closed with 503 and the grant stays pending.
    """)
    live()
    contoso = f"salesforce:opportunity:read:{CONTOSO_OPPORTUNITY}"
    r = agent.request_grant(scopes=[SCOPES[0], contoso])
    over = r.json()
    print(dim("  Requested:"))
    for d in over["scope_descriptions"]:
        print(dim(f"    - {d}"))
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/grants/{over['id']}/approve",
        headers=bearer(tokens["priya"]),
    )
    print(dim("  Priya approves:"))
    body = refused(r, "scope_exceeds_principal")
    check(
        body.get("offending_scopes") == [contoso],
        f"offending scopes {body.get('offending_scopes')}",
    )
    r = httpx.get(
        f"{settings.CONTROL_PLANE_URL}/v1/grants/{over['id']}", headers=bearer(tokens["priya"])
    )
    check(r.json()["status"] == "rejected", "over-scoped grant not marked rejected")
    print(f"  grant {over['id']} is now {red('REJECTED')} - it can never become active")


def step_7_approve(grant_id: str, tokens) -> None:
    step(7, "Priya approves the real request")
    plain("""
        Priya reads the request - plain English, three specific records, 30
        minutes - and approves it. She is not handing over her login. She is
        lending a slice of her own access, and Gatekeep has just proved the
        slice really is hers to lend.
    """)
    technical("""
        Same endpoint, now with Priya's token. Approver check passes; all three
        OpenFGA checks return allowed (two viewer, one editor via `owner from
        parent`). A conditional UPDATE ... WHERE status='pending' moves it to
        active, so a concurrent revoke cannot be overwritten. grant.approved is
        audited.
    """)
    live()
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/grants/{grant_id}/approve",
        headers=bearer(tokens["priya"]),
    )
    check(r.status_code == 200, f"approve returned {r.status_code}: {r.text[:200]}")
    grant_card(r.json())


def step_8_token(agent: Agent, grant_id: str) -> None:
    step(8, "The agent swaps the approval for a 5-minute key   (the delegation token)")
    plain("""
        The agent exchanges Priya's approval for a key card. The card says two
        things at once: WHO authorised this (Priya) and WHO is using it (the
        agent). It lists exactly which records it opens. It stops working in
        five minutes. And it is stamped by a vault that never lets the stamp
        out - not even our own code can see the signing key.

        This is the thing today's tools cannot express: one credential, two
        identities, record-level limits.
    """)
    technical("""
        POST /oauth/token on the token service, RFC 8693 token exchange:
        subject_token = the grant id, actor_token = the bootstrap credential.
        Checks: argon2id credential, grant issued to this agent, grant usable
        (Redis revoked set, then Postgres status/expiry), scope subset. Claims
        per section 6.3: sub = human, act.sub = agent, act.instance = session,
        aud = gatekeep-pep, exp = min(iat+300, grant expiry). Signed RS256 by
        OpenBao transit - the service sends the signing input and receives a
        signature; the private key is non-exportable. The public half is at
        /.well-known/jwks.json with kid gk-signing-v<N>.
    """)
    live()
    r = agent.exchange(grant_id)
    check(r.status_code == 200, f"exchange returned {r.status_code}: {r.text[:200]}")
    body = r.json()
    show_http(
        "POST",
        "/oauth/token",
        r.status_code,
        {k: (v[:40] + "..." if k == "access_token" else v) for k, v in body.items()},
    )
    print()
    token_explained(agent.token)

    header, claims = decode_unverified(agent.token)
    check(
        claims["sub"] == PRINCIPAL and claims["act"]["sub"] == AGENT_ID, "wrong identities in token"
    )
    check(claims["exp"] - claims["iat"] <= 300, "token lives longer than 5 minutes")
    check(sorted(claims["scope"]) == sorted(SCOPES), "token scope differs from grant")

    print()
    jwks = httpx.get(f"{settings.TOKEN_SERVICE_URL}/.well-known/jwks.json").json()
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    jwt.decode(agent.token, jwt.PyJWK(key).key, algorithms=["RS256"], audience="gatekeep-pep")
    outcome(True, f"signature verifies against the published public key {header['kid']}")
    r = httpx.get(
        f"{settings.BAO_URL}/v1/transit/export/signing-key/{settings.SIGNING_KEY}",
        headers={"X-Vault-Token": settings.BAO_TOKEN},
    )
    check(r.status_code >= 400, "OpenBao allowed the signing key to be exported")
    outcome(
        r.status_code >= 400,
        f"asking OpenBao to export the private key: refused (HTTP {r.status_code})",
    )


def step_9_invariant_2(agent: Agent, grant_id: str) -> None:
    step(9, "The agent tries to widen its own key   (Invariant 2)")
    plain("""
        The agent now asks the key cutter for a key that also opens Contoso,
        hoping the approval check was the only gate. It is not. A key can never
        open more than the approval behind it, no matter who asks or how.
    """)
    technical("""
        Same /oauth/token call with scope=salesforce:opportunity:read:0065g00099CTO.
        The token service compares requested scopes against grant.scopes (exact
        string match - no wildcard or prefix logic to get wrong) and returns
        403 scope_exceeds_grant, audited as token.denied. An agent MAY ask for
        fewer scopes than the grant - least privilege per run.
    """)
    live()
    probe = Agent(agent.credential)
    refused(
        probe.exchange(grant_id, scope=f"salesforce:opportunity:read:{CONTOSO_OPPORTUNITY}"),
        "scope_exceeds_grant",
    )


def step_10_work(agent: Agent) -> None:
    step(10, "The agent does its job")
    plain("""
        The agent reads the Northwind opportunity (closed at 48,500), reads the
        invoice (billed 45,200), notices Northwind was under-billed by 3,300,
        and writes a note saying so. Every one of those calls went through
        Gatekeep, was checked, and was written into the evidence log - but only
        a fingerprint of the data was kept, never the customer data itself.
    """)
    technical("""
        Each call is GET/PATCH /proxy/salesforce/services/data/v60.0/sobjects/<Object>/<Id>
        on the PEP, which runs section 7.2's pipeline: (1) verify JWT against
        the token service's JWKS - RS256 only, iss, aud=gatekeep-pep, exp with
        30s leeway; (2) revocation - Redis then Postgres, fail closed;
        (3) the connector maps the request to salesforce:<type>:<read|write>:<id>,
        rejecting anything it does not recognise; (4) that exact string must be
        in the token's scope; (5) OpenFGA re-checks that PRIYA still holds it
        right now - rights can be withdrawn after approval; (6) forward to
        Salesforce with a connector credential only the PEP holds; (7) audit
        access.allowed with a SHA-256 digest of the response. If the audit
        write fails, the data is not returned.
    """)
    live()
    before = arrivals()
    calls = [("GET", "Opportunity", OPPORTUNITY, None), ("GET", "Invoice__c", INVOICE, None)]
    results = {}
    for method, obj, rid, body in calls:
        r = agent.call(method, obj, rid, body)
        check(r.status_code == 200, f"{method} {obj} returned {r.status_code}")
        results[obj] = r.json()
        print(
            f"  {green('ALLOW')}  {method:5} {obj}/{rid:<16} "
            f"{dim(r.headers['x-gatekeep-latency-ms'] + ' ms through the PEP')}"
        )
    o, i = results["Opportunity"], results["Invoice__c"]
    diff = o["Amount"] - i["Amount__c"]
    note = (
        f"August reconciliation: {o['Name']} closed at {o['Amount']:,.2f}; "
        f"invoice {i['Name']} billed "
        f"{i['Amount__c']:,.2f}. Under-billed by {diff:,.2f}. Flagged for finance review."
    )
    r = agent.call("PATCH", "Note", NOTE, {"Body": note})
    check(r.status_code == 200, f"PATCH Note returned {r.status_code}")
    print(
        f"  {green('ALLOW')}  PATCH Note/{NOTE:<16} "
        f"{dim(r.headers['x-gatekeep-latency-ms'] + ' ms through the PEP')}"
    )
    print()
    print(f"  Opportunity  {o['Name']}   {o['Amount']:>12,.2f}")
    print(f"  Invoice      {i['Name']:<28} {i['Amount__c']:>12,.2f}")
    print(f"  {bold('Difference')}   {'':28} {yellow(f'{diff:>12,.2f}')}")
    print(f"  Note written: {dim(note)}")
    print()
    check(arrivals() - before == 3, "Salesforce did not receive exactly the 3 allowed requests")
    print(
        dim(
            f"  Mock Salesforce received {arrivals() - before} requests - "
            "exactly the three that were allowed."
        )
    )


async def step_11_denials(agent: Agent) -> None:
    step(11, "The agent strays - and is stopped   (deny by default)")
    plain("""
        Now the agent misbehaves in four different ways - the kind of thing a
        buggy agent, or one tricked by a malicious document, might do:

          a) reads a record on Contoso, which it was never given
          b) edits its own key card to add Contoso
          c) skips Gatekeep and calls Salesforce directly
          d) tries an action nobody described - deleting a record

        Every attempt is refused, each for a stated reason, each written to the
        evidence log. And none of the refused requests ever reached Salesforce.
    """)
    technical("""
        (a) scope check: salesforce:opportunity:read:0065g00099CTO is not in the
        token -> 403 action_outside_token_scope. (b) payload edited, signature
        unchanged -> RS256 verification fails -> 401 bad_signature. (c) the mock
        Salesforce rejects anything without the PEP's connector credential ->
        401; in production this is network egress policy, a deployment
        requirement (docs/SECURITY.md 9.1). (d) DELETE is not a mapped action ->
        403 unmapped_request. Every PEP denial is audited as access.denied with
        its reason; an unexpected exception also denies (503), never forwards.
    """)
    live()
    before = arrivals()

    print(bold("  a) Read a Contoso opportunity"))
    r = agent.call("GET", "Opportunity", CONTOSO_OPPORTUNITY)
    refused(r, "action_outside_token_scope")
    print(dim(f"           decided in {r.headers.get('x-gatekeep-latency-ms')} ms"))

    print(bold("\n  b) Forge the token: add Contoso to its scope"))
    head, payload, sig = agent.token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["scope"].append(f"salesforce:opportunity:read:{CONTOSO_OPPORTUNITY}")
    forged_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    forged = f"{head}.{forged_payload}.{sig}"
    refused(
        agent.call("GET", "Opportunity", CONTOSO_OPPORTUNITY, token=forged), "bad_signature", 401
    )

    print(bold("\n  c) Bypass Gatekeep, call Salesforce directly"))
    url = (
        f"{settings.MOCK_SALESFORCE_URL}/services/data/v60.0/sobjects/Opportunity/"
        f"{CONTOSO_OPPORTUNITY}"
    )
    r = httpx.get(url, headers=bearer(agent.token))
    check(r.status_code == 401, f"direct Salesforce call returned {r.status_code}")
    print(
        f"  {red('REFUSED')}  HTTP {r.status_code}  {r.json()[0]['errorCode']} "
        "- the agent holds no Salesforce credential"
    )

    print(bold("\n  d) Delete the note"))
    refused(agent.call("DELETE", "Note", NOTE), "unmapped_request")

    after = arrivals()
    print()
    # Only (c) arrives at Salesforce at all - and it arrives unauthenticated and is refused there.
    check(
        after - before == 1,
        f"expected only the direct bypass attempt to arrive, got {after - before}",
    )
    outcome(
        after - before == 1,
        "Salesforce saw none of the PEP-refused requests "
        "(only the direct attempt, which it rejected)",
    )


def step_12_killswitch(agent: Agent, tokens) -> None:
    step(12, "The kill switch")
    plain("""
        Something looks wrong - say, a report that agents are being fed
        malicious instructions. The security admin presses one button. Every
        agent permission across the company is cancelled at once. The agent,
        which still holds a key card that has not expired, is refused on its
        very next request - within milliseconds, not when the card runs out.

        Priya, an ordinary user, cannot press this button.
    """)
    technical("""
        GET /v1/killswitch/preview then POST /v1/killswitch (security-admin
        role). One Postgres transaction revokes every pending/active grant and
        marks running sessions killed; after commit the grant ids are added to
        the Redis revoked set, then killswitch.activated and one grant.revoked
        per grant are audited. The PEP checks revocation on every request, so
        the still-valid 5-minute token is dead immediately; the token service
        re-checks on refresh, so no new token can be minted. If Redis were
        empty or down, Postgres would still say revoked - it is the authority.
    """)
    live()
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/killswitch",
        headers=bearer(tokens["priya"]),
        json={"reason": "test"},
    )
    print(dim("  Priya tries the kill switch:"))
    refused(r, "forbidden")

    r = agent.call("GET", "Opportunity", OPPORTUNITY)
    check(r.status_code == 200, "agent should still be working before the kill")
    print(f"\n  agent right before:  {green('ALLOW')}  GET Opportunity/{OPPORTUNITY}")

    p = httpx.get(
        f"{settings.CONTROL_PLANE_URL}/v1/killswitch/preview", headers=bearer(tokens["admin"])
    ).json()
    print(
        f"\n  {red(bold('KILL SWITCH'))}  will revoke {bold(str(p['grants_to_revoke']))} grant(s), "
        f"stop {bold(str(p['sessions_to_kill']))} running session(s)"
    )
    started = time.perf_counter()
    r = httpx.post(
        f"{settings.CONTROL_PLANE_URL}/v1/killswitch",
        headers=bearer(tokens["admin"]),
        json={"reason": "suspected prompt injection"},
    )
    check(r.status_code == 200, f"kill switch returned {r.status_code}")
    k = r.json()
    r = agent.call("GET", "Opportunity", OPPORTUNITY)
    elapsed_ms = (time.perf_counter() - started) * 1000
    print(
        f"  activated by {k['activated_by']}: {k['grants_revoked']} grant(s) revoked, "
        f"{k['sessions_killed']} session(s) killed"
    )
    for n in range(k["sessions_killed"], -1, -1):
        print(f"\r  running sessions: {bold(str(n))} ", end="", flush=True)
        time.sleep(0.2)
    print()
    print("\n  agent right after, token still unexpired:")
    refused(r, "grant_revoked")
    check(elapsed_ms < 5000, f"revocation took {elapsed_ms:.0f} ms, over the 5 second budget")
    outcome(
        elapsed_ms < 5000,
        f"button press to first refused request: {bold(f'{elapsed_ms:.0f} ms')} (budget 5,000 ms)",
    )
    print()
    print(dim("  The agent tries to refresh its token:"))
    refused(agent.exchange(agent.grant_id, refresh=True), "grant_revoked")


async def step_13_auditor(tokens) -> None:
    step(13, "The auditor checks the evidence - and catches a cover-up")
    plain("""
        Months later an auditor asks: what did this agent do, on whose
        authority, and what was it stopped from doing? Everything above is in
        the log - approvals, refusals, every record read, the kill switch.

        Each entry is locked to the one before it, like links in a chain. The
        auditor runs the checker: the chain is intact. Then someone with direct
        database access quietly changes one refusal to look like it was
        allowed. The row looks perfectly normal. The checker names the exact
        entry that was changed.
    """)
    technical("""
        GET /v1/audit (auditor or security-admin) and GET /v1/audit/verify, which
        walks the chain from genesis: entry_hash = SHA-256(prev_hash +
        canonical JSON of 11 fields, sorted keys, fixed separators). Writes take
        pg_advisory_xact_lock so concurrent writers from three services never
        fork the chain. The services' Postgres role has no UPDATE or DELETE on
        audit_events - the edit below needs the table owner, i.e. a DBA. This is
        tamper-EVIDENCE, not tamper-proofing: we cannot stop the edit, we
        guarantee it is detectable. `make audit-verify` runs the same check
        straight against the database, without our services.
    """)
    live()
    h = bearer(tokens["auditor"])
    events = httpx.get(
        f"{settings.CONTROL_PLANE_URL}/v1/audit", params={"limit": 200}, headers=h
    ).json()["events"]
    audit_table(list(reversed(events)))
    kinds = {e["event_type"] for e in events}
    for needed in (
        "grant.requested",
        "grant.approved",
        "grant.rejected",
        "token.issued",
        "token.denied",
        "access.allowed",
        "access.denied",
        "killswitch.activated",
        "grant.revoked",
    ):
        check(needed in kinds, f"no {needed} event in the audit trail")
    check(
        all(e["payload_digest"] is None or len(e["payload_digest"]) == 64 for e in events),
        "payload_digest is not a SHA-256 hex digest",
    )

    print()
    v = httpx.get(f"{settings.CONTROL_PLANE_URL}/v1/audit/verify", headers=h).json()
    check(v["valid"], "chain should be intact before tampering")
    print(f"  {green('CHAIN INTACT')}   {v['message']}")

    target = next(
        e
        for e in reversed(events)
        if e["event_type"] == "access.denied" and e["reason"] == "action_outside_token_scope"
    )
    seq = target["seq"]
    print()
    print(
        f"  Entry {seq}: {target['resource']}  "
        f"decision={red(target['decision'])}  ({target['reason']})"
    )
    print(dim("  A database administrator hides the refusal:"))
    print(dim(f"      UPDATE audit_events SET decision = 'allow' WHERE seq = {seq};"))
    conn = await asyncpg.connect(OWNER_DSN)
    try:
        await conn.execute("UPDATE audit_events SET decision = 'allow' WHERE seq = $1", seq)
    finally:
        await conn.close()
    print(
        f"  Entry {seq} now: decision={green('allow')}   {dim('- the row looks perfectly normal')}"
    )
    print()
    v = httpx.get(f"{settings.CONTROL_PLANE_URL}/v1/audit/verify", headers=h).json()
    check(not v["valid"], "verifier missed the edit")
    check(v["broken_at_seq"] == seq, f"verifier named entry {v['broken_at_seq']}, expected {seq}")
    print(f"  {red('CHAIN BROKEN')}   {v['message']}")
    print()
    print(bold("  That is what you hand a regulator."))

    print()
    app_conn = await asyncpg.connect(settings.APP_DSN)
    try:
        try:
            await app_conn.execute("UPDATE audit_events SET decision = 'allow' WHERE seq = $1", seq)
            check(False, "gatekeep_app was allowed to UPDATE the audit chain")
        except asyncpg.InsufficientPrivilegeError:
            outcome(True, "the same UPDATE as the services' own database role: refused by Postgres")
    finally:
        await app_conn.close()


def step_14_summary() -> None:
    step(14, "What you just saw")
    print(
        wrap(
            """
        Delegation         The agent acted for Priya with a strict subset of her
                           authority. Only she could approve; she could not lend
                           what she lacks (Invariant 1); the token could not
                           exceed the grant (Invariant 2). sub = Priya, act = agent.

        Fine-grained scope Three named records, read vs write, 30 minutes - not
                           "Salesforce API access".

        Defensible audit   Every decision, allowed or refused, chained. Record
                           contents never stored, only digests. An edit to history
                           was caught and located.

        Instant revocation One button, every grant, refused on the next request.
    """,
            2,
        )
    )
    if not BRIEF:
        print("\n" + bold("  Stated limitations (docs/SECURITY.md)"))
        print(
            wrap(
                """
            Agent identity is a bootstrap credential; SPIFFE attestation is Phase 2.
            The connector is a mock Salesforce; the real connector is Phase 2.
            Egress control is a deployment requirement we specify, not something
            this laptop demo enforces. Policy tuples are seeded, not synced.
            Constraints (max_records, rate_limit_rpm) are carried in the token but
            not yet enforced. A denial's free-text reason is outside the hash.
        """,
                4,
            )
        )


# --- runner ---------------------------------------------------------------------


def preflight() -> None:
    names = {8000: "control plane", 8001: "token service", 8002: "PEP", 8003: "mock Salesforce"}
    down = []
    for port, name in names.items():
        try:
            httpx.get(f"http://localhost:{port}/healthz", timeout=3).raise_for_status()
        except httpx.HTTPError:
            down.append(f"{name} (:{port})")
    if down:
        raise SystemExit(
            f"\n  Not running: {', '.join(down)}\n\n" f"  In another terminal:  make services\n"
        )


async def main(reset: bool) -> int:
    preflight()
    if reset:
        print(dim("  resetting demo state (make demo-reset)..."))
        subprocess.run([sys.executable, "tools/demo_reset.py"], check=True, capture_output=True)

    print()
    print(bold("  GATEKEEP"))
    print(
        dim(
            "  Agent authorization: delegation, record-level scope, "
            "defensible audit, instant revocation."
        )
    )

    step_1_the_problem()
    tokens = step_2_the_cast()
    agent = await step_3_register(tokens)
    grant_id = step_4_request(agent, tokens)
    step_5_wrong_approver(grant_id, tokens)
    step_6_overreach(agent, tokens)
    step_7_approve(grant_id, tokens)
    step_8_token(agent, grant_id)
    step_9_invariant_2(agent, grant_id)
    step_10_work(agent)
    await step_11_denials(agent)
    step_12_killswitch(agent, tokens)
    await step_13_auditor(tokens)
    step_14_summary()

    print("\n" + bold("=" * 78))
    if failures:
        print(red(f"  {len(failures)} check(s) did not behave as expected:"))
        for f in failures:
            print(red(f"    - {f}"))
        print(bold("=" * 78) + "\n")
        return 1
    print(green("  Every step behaved as expected."))
    print(
        dim(
            "  The audit chain was deliberately broken in step 13. "
            "`make demo-reset` before the next run."
        )
    )
    print(bold("=" * 78) + "\n")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--pause", action="store_true", help="stop between steps")
    ap.add_argument("--brief", action="store_true", help="results only, no explanations")
    ap.add_argument("--no-reset", action="store_true", help="do not reset demo state first")
    args = ap.parse_args()
    PAUSE, BRIEF = args.pause, args.brief
    try:
        sys.exit(asyncio.run(main(reset=not args.no_reset)))
    except (httpx.ConnectError, OSError) as e:
        print(f"\n  Cannot reach a dependency: {e}")
        print("  Is everything up?   make dev && make migrate && make seed, then make services\n")
        sys.exit(2)
