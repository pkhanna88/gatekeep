# Gatekeep demo guide

There is no web console yet, so the demo runs in a terminal. This guide covers
how to run it and what every step shows, in two ways:

- **In plain words:** what a business person sees and why they care.
- **Technically:** which service does what, which endpoint, and which check.

Everything in the demo is real. The agent's requests go through the real token
service and PEP. Priya logs in through Keycloak. Permissions come from OpenFGA,
the signing key stays in OpenBao, and the audit trail is the real Postgres table.
The only stand-in is Salesforce itself, which is a local mock (see
[CONNECTOR-NOTES.md](CONNECTOR-NOTES.md)).

---

## 1. Running it

### One-time setup

```bash
make setup      # virtual environment and dependencies
make dev        # Postgres, Redis, Keycloak, OpenFGA, OpenBao - waits until healthy
make migrate    # tables: audit_events, agents, grants, agent_sessions
make seed       # permission model and facts, plus the token-signing key
```

### Every time

In one terminal, start Gatekeep's own services and leave them running:

```bash
make services   # control plane :8000, token service :8001, PEP :8002, mock Salesforce :8003
```

Then pick one of the two ways to present it.

### Option A: the narrated script (recommended for a first showing)

```bash
make demo PAUSE=1   # stops between steps; press Enter to continue
make demo           # runs straight through
make demo BRIEF=1   # results only, no explanations (the timed run; CI runs this)
```

The script resets the demo state itself, runs all 14 steps, prints a **WHAT IS
HAPPENING** and an **UNDER THE HOOD** section for each, and shows the live
calls and results. It checks every expected outcome and exits non-zero if
anything does not behave. Step 13 deliberately corrupts the audit trail, so run
`make demo-reset` before a second run.

### Option B: live, three terminals (for questions and "show me")

This shows a running agent being stopped in real time.

| Terminal 1 | Terminal 2 | Terminal 3 |
|---|---|---|
| `make services` | `make demo-reset` then `.venv/bin/python tools/agent.py --loop` | the commands below |

In terminal 3, act as each person:

```bash
make gk ARGS="pending --as priya"                    # Priya's approval queue
make gk ARGS="approve gr_... --as priya"             # terminal 2 starts working
make gk ARGS="watch --as auditor"                    # live audit feed (Ctrl+C to stop)
make gk ARGS="sessions --as admin --status running"
make gk ARGS="killswitch --as admin --reason 'suspected prompt injection'"
                                                     # terminal 2 is refused on its next call
make gk ARGS="audit --as auditor --limit 40"
make gk ARGS="verify --as auditor"
make audit-verify                                    # same check, straight from the database
```

Every `gk` command logs in through Keycloak as that person and calls the same
API a web console would, so the same permission checks apply. For example, try
`killswitch --as priya`.

The API is also browsable at http://localhost:8000/docs (control plane) and
http://localhost:8001/docs (token service).

---

## 2. The cast and the data

| Who | Login | Role | What they can touch |
|---|---|---|---|
| Priya | `priya@acme.test` / `priya` | analyst | Owns Northwind Traders, so she can read and write its records |
| Security admin | `admin@acme.test` / `admin` | security-admin | Registers agents and uses the kill switch. **No access to customer data**, deliberately |
| Auditor | `auditor@acme.test` / `auditor` | auditor | Reads the audit trail. Can view Northwind but not write to it |
| The agent | `agent://acme/invoice-reconciler` | none | Only what Priya lends it |

| Record | Customer | Contents (mock Salesforce) |
|---|---|---|
| Opportunity `0065g00001NWD` | Northwind Traders | August renewal, closed at 48,500.00 |
| Invoice `0INV00001NWD` | Northwind Traders | INV-2026-0817, billed 45,200.00 |
| Note `0NOT00001NWD` | Northwind Traders | Where the agent writes its finding |
| Opportunity `0065g00099CTO` | Contoso Ltd | **Nobody** has access. This is the record the agent must not reach |

The agent's job is to spot that Northwind was under-billed by 3,300.00 and
write a note saying so.

---

## 3. The map

```
   Priya / admin / auditor                       the agent (tools/agent.py)
          |                                          |          |           |
          | log in (OIDC)                   request  | exchange |   every   |
          v                                  grant   |  grant   |  API call |
   +--------------+                                  v          v           v
   |   Keycloak   |  :8080      +----------------------+  +-----------+  +-----------+
   | human login  |------------>|    Control plane     |  |   Token   |  | PEP proxy |
   +--------------+   tokens    |        :8000         |  |  service  |  |   :8002   |
                                | agents, grants,      |  |   :8001   |  |           |
   gk.py (console stand-in) --->| approvals, kill      |  | RFC 8693  |  | 7 checks  |
                                | switch, audit search |  | exchange  |  | then      |
                                +----------------------+  +-----------+  | forward   |
                                   |      |      |          |     |      +-----------+
                                   |      |      |          |     |        |   |   |
              +--------------------+      |      +----------|-----|--------+   |   |
              v                           v                 v     v            |   v
      +---------------+          +----------------+   +-----------+            | +------------------+
      |    OpenFGA    |  :8081   |    Postgres    |   |  OpenBao  |  :8200     | | Mock Salesforce  |
      | who may touch |          | grants, agents,|   | signing   |            | |      :8003       |
      | which record  |          | sessions,      |   | key never |            | | answers only the |
      +---------------+          | AUDIT CHAIN    |   | leaves    |            | | PEP's credential |
                                 +----------------+   +-----------+            | +------------------+
                                 +----------------+                            |
                                 |     Redis      |  :6379  <------------------+
                                 | revoked grants |
                                 +----------------+
```

**In plain words:** Keycloak says who a person is. The control plane is the
front desk, where permission is asked for, granted and cancelled. The token
service cuts short-lived key cards. The PEP is the guard every agent request
must pass. OpenFGA knows who may touch which record. OpenBao holds the stamp
that makes key cards genuine. Postgres keeps the records and the tamper-evident
log. Redis is a fast "cancelled" list.

---

## 4. The demo, step by step

Each step matches a step in `make demo`. The "By hand" commands do the same
thing in Option B.

### Step 1: The problem

**In plain words.** Priya wants an AI agent to reconcile one customer's
invoices. Today security offers her two bad options:

- **A service account:** a master key to all of Salesforce that never expires
  and logs everything as "svc-agent".
- **Her own login:** every action looks like Priya did it, so nobody can tell
  the person from the machine.

Gatekeep is the third option. Priya lends the agent a small, specific,
short-lived slice of her own access, and every use of it is provable.

**Technically.** This is the problem statement from the handbook's Part 1.
Nothing runs yet.

### Step 2: Who is who

**In plain words.** Three people log in through the company's normal login
system, and Gatekeep never sees a password. Being a senior security admin does
not mean seeing customer data.

**Technically.**
- Keycloak issues an OIDC access token for each user.
- The control plane verifies four things on every call: the RS256 signature
  against Keycloak's JWKS, the issuer, the expiry, and
  `aud = gatekeep-control-plane`.
- People are identified by the `principal` claim (their email), not by `sub`,
  which is Keycloak's opaque UUID. That makes a switch to Okta or Entra a
  single claim mapping.
- Roles come from `realm_access.roles`.

*Code:* `services/control-plane/app/humans.py`, `app/jwtverify.py`

### Step 3: The agent gets an identity

**In plain words.** A security admin registers the agent and it receives a
secret password of its own, shown once. Gatekeep keeps only a scrambled
fingerprint, so a stolen database does not reveal the password. The password
proves *who* the agent is. On its own it grants no access. Priya is refused
when she tries to register an agent.

**Technically.**
- `POST /v1/agents` requires the security-admin role.
- The credential format is `gkb.<key_id>.<secret>`. The `key_id` is a public
  lookup handle and the secret is 32 random bytes.
- Only an argon2id hash is stored.
- An unknown `key_id` still runs a dummy hash check, so response timing does
  not reveal whether the id or the secret was wrong.
- This is the weak point we disclose: a bootstrap credential, not SPIFFE
  workload attestation (SECURITY.md 8.1).

*By hand:* `make gk ARGS="agents --as admin"`
*Code:* `services/control-plane/app/agents.py`

### Step 4: The agent asks Priya for permission

**In plain words.** The agent asks: "Let me read this opportunity and this
invoice, and write one note, on Northwind, for 30 minutes, to reconcile August
invoices." The request lands in Priya's queue in plain English. Until she
approves, the agent has nothing, and a request for a key card now is refused.

**Technically.**
- `POST /v1/grants` is authenticated with the agent's bootstrap credential. The
  `agent_id` in the body must match that credential.
- Scopes are `system:resource_type:action:resource_id` and parsed strictly.
  Unknown systems, types or actions, malformed ids, and wildcards all return
  400.
- The grant is stored as `pending` with an absolute `expires_at`, and
  `grant.requested` is written to the audit trail.
- A token exchange now returns `403 grant_pending`.

*By hand:* `make gk ARGS="pending --as priya"`
*Code:* `app/grants.py` (`request_grant`), `app/scopes.py`

### Step 5: Someone else tries to approve it

**In plain words.** The security admin tries to approve on Priya's behalf and
is refused. Only Priya can lend Priya's access. Otherwise the record would say
Priya authorised something she never saw. The attempt is logged, and the grant
waits for Priya.

**Technically.**
- `POST /v1/grants/{id}/approve` checks that the approver's `principal` equals
  the grant's `principal_sub`. This runs before any other check (handbook §7.1).
- A mismatch returns `403 approver_is_not_principal` and writes
  `grant.rejected` to the audit trail with the reason.
- The grant stays `pending`.

*By hand:* `make gk ARGS="approve gr_... --as admin"`
*Code:* `app/grants.py` (`approve_grant`)

### Step 6: The agent asks for more than Priya has (Invariant 1)

**In plain words.** A second request slips in a Contoso record, which Priya
cannot access herself. Even if Priya approves without reading carefully,
Gatekeep checks every item against what Priya actually holds, refuses the
whole grant, and names the item. **You cannot lend what you do not have.**

**Technically.**
- On approval, each scope becomes one OpenFGA `check` as the principal:
  - `read` checks `viewer` and `write` checks `editor`.
  - The object is `type:id`.
- Priya's access to Northwind records is *inherited*: opportunity → parent
  account → owner.
- All failures are collected and returned together as
  `403 scope_exceeds_principal` with `offending_scopes`.
- The grant becomes `rejected` permanently, and the refusal is audited.
- If OpenFGA cannot answer, approval is refused with 503 and the grant stays
  pending. We never approve on a check we could not run.

*By hand:* have the agent request a Contoso scope, then
`make gk ARGS="approve gr_... --as priya"`
*Code:* `app/grants.py`, `app/fga.py`, `policy/fga-model.fga`
*Test:* `test_grant_cannot_exceed_principal`, `test_read_only_user_cannot_delegate_write`

### Step 7: Priya approves the real request

**In plain words.** Priya reads three specific records, 30 minutes, a clear
purpose, and approves. She is not handing over her login. She is lending a
slice of her own access, and Gatekeep has just proved it is hers to lend.

**Technically.**
- The approver check passes, and all three OpenFGA checks return allowed: two
  `viewer`, and one `editor` through `owner from parent`.
- A conditional `UPDATE ... WHERE status = 'pending'` activates the grant, so a
  concurrent revoke cannot be overwritten.
- `grant.approved` is written to the audit trail.

*By hand:* `make gk ARGS="approve gr_... --as priya"`

### Step 8: The agent gets a 5-minute key card (the delegation token)

**In plain words.** The agent trades Priya's approval for a key card that
carries two names: **who authorised it** (Priya) and **who is using it** (the
agent). It lists exactly which records it opens and stops working after five
minutes. It is stamped by a vault that never releases the stamp, so even
Gatekeep's own code never sees the signing key. Today's identity tools have no
way to express this: one credential, two identities, record-level limits.

**Technically.** The token service handles `POST /oauth/token` as an RFC 8693
token exchange. The request carries:
- `subject_token`: the grant id, which is whose authority is used
- `actor_token`: the bootstrap credential, which is who is acting

The token service checks, in order:
1. The credential verifies (argon2id) and the agent is active.
2. The grant was issued to this agent.
3. The grant is usable: not in the Redis revoked set, and `active` and
   unexpired in Postgres.
4. **Invariant 2:** the requested scope is within the grant's scope.

The token's claims (handbook §6.3):
- `sub`: Priya
- `act.sub`: the agent
- `act.instance`: the session id
- `aud`: `gatekeep-pep`
- `scope`: the three records
- `exp`: the earlier of issue time + 300 seconds and the grant's expiry

Signing:
- The token service builds the JWT signing input and sends it to OpenBao
  transit.
- Transit returns `vault:v1:<signature>`, which is re-encoded to base64url.
- The header's `kid` is `gk-signing-v<N>`, the transit key version.
- Public keys are published at `/.well-known/jwks.json`.
- The demo verifies the signature against JWKS, then shows OpenBao refusing to
  export the private key.

*By hand:* `make gk ARGS="decode <token>"` explains any token.
*Code:* `services/token-service/token_service/exchange.py`, `signing.py`
*Test:* `test_token_carries_both_identities`, `test_token_signature_verifies_against_jwks`

### Step 9: The agent tries to widen its own key (Invariant 2)

**In plain words.** The agent asks for a key card that also opens Contoso. A
key card can never open more than the approval behind it.

**Technically.**
- The same `/oauth/token` call is sent with
  `scope=salesforce:opportunity:read:0065g00099CTO`.
- The requested scopes are compared with `grant.scopes` by exact string match,
  with no wildcard or prefix logic.
- Result: `403 scope_exceeds_grant`, audited as `token.denied`.
- Asking for *fewer* scopes than the grant is allowed, which gives least
  privilege per run.

*Test:* `test_token_scope_subset_of_grant`, `test_another_agent_cannot_use_the_grant`

### Step 10: The agent does its job

**In plain words.** The agent reads the opportunity (48,500), reads the invoice
(45,200), finds the 3,300 under-billing, and writes a note. Each call passed
through Gatekeep and was checked and logged. The log keeps only a fingerprint
of the data, never the customer data itself. Mock Salesforce received exactly
three requests.

**Technically.** Each call is
`GET` or `PATCH /proxy/salesforce/services/data/v60.0/sobjects/<Object>/<Id>`
on the PEP, which runs this pipeline:

| # | Check | Refusal |
|---|---|---|
| 1 | JWT verified against the token service's JWKS: RS256 only, `iss`, `aud`, `exp` with 30 s leeway, delegation claims present | 401 `bad_signature`, `token_expired`, `unknown_signing_key`, ... |
| 2 | Revocation: Redis revoked set, then the grant row in Postgres | 403 `grant_revoked`, `grant_expired` |
| 3 | The connector maps the request to `salesforce:<type>:<read\|write>:<id>`. Only single-record GET and PATCH are recognised | 403 `unmapped_request` |
| 4 | That exact scope string must be in the token | 403 `action_outside_token_scope` |
| 5 | OpenFGA re-checks that **Priya still holds it now** | 403 `policy_denied` |
| 6 | Forward to Salesforce with a connector credential only the PEP holds. The URL is rebuilt from the parsed action, not copied from the agent | — |
| 7 | Audit `access.allowed` with the SHA-256 of the response. **If this write fails, the data is not returned** | 503 |

Any unexpected error returns `503 authorization_unavailable` and is never
forwarded. Every response carries `X-Gatekeep-Decision` and
`X-Gatekeep-Latency-Ms` headers.

*Code:* `services/pep-proxy/pep_proxy/pipeline.py`, `connectors/mock.py`
*Test:* `test_allowed_request_reaches_salesforce`, `test_no_response_bodies_in_audit`,
`test_policy_denial_after_rights_withdrawn`

### Step 11: The agent strays and is stopped (deny by default)

**In plain words.** The agent misbehaves in four ways, the kind of thing a
buggy agent or one tricked by a malicious document might do. Each attempt is
refused with a stated reason and logged, and nothing the PEP refused ever
reaches Salesforce.

| Attempt | Result | Why |
|---|---|---|
| a) Read the Contoso opportunity | 403 `action_outside_token_scope` | Not on its key card. Decided in a few milliseconds |
| b) Edit its own token to add Contoso | 401 `bad_signature` | Changing any part of the token breaks the vault's stamp |
| c) Skip Gatekeep and call Salesforce directly | 401 `INVALID_SESSION_ID` from Salesforce | The agent holds no Salesforce credential |
| d) Delete the note | 403 `unmapped_request` | Nobody described that action, so it is refused |

**Technically.**
- Mock Salesforce logs every request that *arrives* (`/_gatekeep/requests`).
  The demo compares counts before and after: only attempt (c) arrived, and
  Salesforce rejected it.
- In production, attempt (c) is blocked by network egress policy, which is a
  deployment requirement (SECURITY.md 9.1). Locally it is blocked by
  credential isolation.

*Test:* `test_out_of_scope_request_denied`, `test_tampered_token_denied`,
`test_wrong_key_token_denied`, `test_alg_none_and_hs256_denied`,
`test_unmapped_request_denied`, `test_unknown_exception_denies`

### Step 12: The kill switch

**In plain words.** Suppose agents are being fed malicious instructions. The
security admin presses one button and every agent permission in the company is
cancelled at once. The agent still holds an unexpired key card, but its next
request is refused within milliseconds, not when the card runs out. It cannot
get a new card either. Priya cannot press the button.

**Technically.**
- `GET /v1/killswitch/preview` shows how many grants and sessions will be
  stopped. It stands in for the console's confirmation dialog.
- `POST /v1/killswitch` requires the security-admin role. In **one Postgres
  transaction**, every pending or active grant becomes `revoked` and every
  running session becomes `killed`.
- After the commit, the grant ids are added to the Redis revoked set.
- `killswitch.activated` and one `grant.revoked` per grant are written to the
  audit trail.
- The PEP checks revocation on every request, so the live token dies at once.
  The token service re-checks on refresh, so no new token can be issued.
- Redis only speeds up denials. Postgres is checked for every allow, so an
  empty or crashed Redis never lets a revoked grant through.
- The demo measures the time from button press to the first refused request,
  typically 15–30 ms on a laptop. The budget is 5 seconds.

*By hand:* `make gk ARGS="killswitch --as admin --reason '...'"` while
`tools/agent.py --loop` runs in another terminal.
*Code:* `app/killswitch.py`, `app/revocation.py`
*Test:* `test_killswitch_terminates_all_sessions`, `test_killswitch_requires_admin`,
`test_revoked_grant_denies_immediately`, `test_revocation_survives_redis_flush`

### Step 13: The auditor checks the evidence and catches a cover-up

**In plain words.** Months later an auditor asks what the agent did, on whose
authority, and what it was stopped from doing. Everything is in the log, and
each entry is locked to the one before it like links in a chain. The checker
says the chain is intact.

Then someone with direct database access changes one refusal to "allow". The
row looks normal, but the checker names the exact entry that was changed. This
is what you hand a regulator. The same edit, attempted through Gatekeep's own
database account, is refused by the database.

**Technically.**
- `GET /v1/audit` requires the auditor or security-admin role.
- `GET /v1/audit/verify` walks the chain from genesis. Each
  `entry_hash = SHA-256(prev_hash + canonical JSON)` of 11 fixed fields, with
  sorted keys and fixed separators.
- Writes from all three services take `pg_advisory_xact_lock`, so concurrent
  writers never fork the chain.
- The services' database role, `gatekeep_app`, has no UPDATE or DELETE on
  `audit_events`, so the tampering edit needs the table owner.
- The verifier tells the two kinds of damage apart: an edited row (its contents
  no longer match its hash) and a removed or reordered row (the link to the
  previous entry is broken).
- `make audit-verify` runs the same check directly against the database,
  without Gatekeep's services.
- **This is tamper-evidence, not tamper-proofing.** Nobody can stop a DBA
  editing a row, but the edit cannot go unnoticed.

*Code:* `app/audit.py` (INF), `app/audit_api.py`, `tools/audit_verify.py`
*Test:* `tests/test_audit_chain.py`

### Step 14: What you just saw

| Property | Shown by |
|---|---|
| **Delegation** | Steps 5–9: only Priya approves, she cannot lend what she lacks, the token cannot exceed the grant, and `sub` = Priya with `act.sub` = agent |
| **Fine-grained scope** | Steps 4, 10, 11: three named records with read and write kept separate, not "Salesforce access" |
| **Defensible audit** | Step 13: every decision is chained, data is stored only as digests, and an edit is caught and located |
| **Instant revocation** | Step 12: one button, every grant, refused on the next request |

---

## 5. Reading the refusals

Every refusal has a stable `error` code for software and a `message` for
people.

| Code | Where | Meaning |
|---|---|---|
| `forbidden` | control plane | Your role does not allow this |
| `approver_is_not_principal` | control plane | Only the named human may approve |
| `scope_exceeds_principal` | control plane | Invariant 1: the human does not hold a requested scope |
| `invalid_scope` | control plane, token | Malformed or wildcard scope |
| `grant_pending` / `grant_rejected` / `grant_revoked` / `grant_expired` | token, PEP | The grant is not usable right now |
| `grant_not_issued_to_this_agent` | token | Another agent's grant |
| `scope_exceeds_grant` | token | Invariant 2: the token would exceed the grant |
| `session_not_running` | token | Refresh of a stopped session |
| `missing_bearer_token`, `malformed_token`, `bad_signature`, `unknown_signing_key`, `unsupported_algorithm`, `token_expired`, `wrong_audience`, `wrong_issuer` | PEP | Token verification failed |
| `unmapped_request` | PEP | The request is not a recognised single-record read or write |
| `action_outside_token_scope` | PEP | The token does not cover this record and action |
| `policy_denied` | PEP | The human no longer holds this record |
| `authorization_unavailable` (503) | PEP | A dependency failed. We refuse rather than guess |

---

## 6. Questions you will be asked

These are the handbook's §10.2 questions, with answers that match what is built.

- **"What stops the agent calling Salesforce directly?"** In production,
  network egress policy, which is a deployment requirement we specify. In this
  demo the agent holds no Salesforce credential, and step 11c shows a direct
  call refused.
- **"How do you know the agent is really the agent?"** Today, a bootstrap
  credential checked at token exchange. SPIFFE attestation is Phase 2. Say this
  before you are asked.
- **"What if Gatekeep goes down?"** Agents lose access. We fail closed, and
  that is the right default for a security product.
- **"Latency?"** Quote the `X-Gatekeep-Latency-Ms` values from step 10:
  single-digit milliseconds on a laptop after warm-up. A proper p99
  measurement is still to do.
- **"Our identity provider?"** OIDC. Keycloak here, and Okta or Entra in
  production is a matter of mapping one claim.
- **"Where does our data go?"** Nowhere. We store digests, never record
  contents (step 10).
- **"Isn't this an API gateway?"** A gateway authenticates a service. We carry
  a *human's* delegated authority, per record, through to a machine action, and
  prove it afterwards (steps 8 and 13).
- **"Why is there no UI?"** It was scheduled for a role that was not staffed.
  Everything the UI would do exists as an API and in `tools/gk.py`.

What is not built yet is listed in [SECURITY.md](SECURITY.md) §8: constraints
are not enforced, Salesforce is a mock, there is no web console, and there is
no signed export.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `Not running: control plane (:8000)...` | `make services` in another terminal |
| A service exits at startup | The stack is not up or not seeded: `make dev && make migrate && make seed` |
| `agent_exists` when starting `tools/agent.py` | The credential was shown once and is gone: `make demo-reset` |
| `CHAIN BROKEN` on a fresh run | Step 13 broke it on purpose last time: `make demo-reset` |
| Approval returns 503 `policy_unavailable` | OpenFGA restarted and lost its in-memory store: `make seed` |
| Token exchange returns 503 `signing_unavailable`, or every PEP call returns `bad_signature` | OpenBao restarted and dev mode forgot the key. Run `make seed`, then restart `make services` so the PEP drops its cached public key |
| Everything returns 401 after a long pause | Keycloak tokens last 5 minutes. `gk` logs in fresh on every command, so rerun it |
