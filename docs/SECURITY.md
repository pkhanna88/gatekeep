# Gatekeep — security posture and honest limitations

**Status: Day 8 draft.** The control plane, token service and PEP now exist,
so the statuses below reflect running, tested code (`tests/test_delegation.py`).
Completed Day 19, after the Day 22 adversarial day has produced findings to
record.

This document is written for a customer's security architect, not for us. It is
deliberate that it leads with what we do not do. §3.11: *CISOs respect a team
that volunteers its own limitations, and it becomes a natural upsell
conversation. Hiding it and being caught is far worse than disclosing it.*

Sections marked **[Day 8]** or **[Day 19]** are structural placeholders. They
are listed rather than omitted so that nothing quietly fails to get written.

---

## Legend

Every claim below carries its real implementation status. A security document
that describes an intended system is worse than no document.

| | Meaning |
|---|---|
| ✅ | Implemented and covered by a test that runs in CI |
| 🔶 | Designed and specified; not yet built |
| ⬜ | Not started |

---

## 1. What Gatekeep is for

An agent acting on behalf of a named human, carrying a strict subset of that
human's authority, for a few minutes, with every action provable afterwards.

The problem it solves is that an enterprise putting an agent into production
today chooses between a service account (over-privileged, immortal, and
anonymous in every downstream log) and handing the agent a human's own token
(which destroys the ability to distinguish human action from machine action).
Gatekeep is the third option.

### The four properties

| Property | Meaning | Status |
|---|---|---|
| Delegation | The agent acts as a named human, never more than that human holds | ✅ Invariants 1 and 2, `sub`/`act.sub` token |
| Fine-grained scope | Authority per record and per action, not per application | ✅ policy model and PEP enforcement |
| Defensible audit | A verifiable chain from human intent to individual record actions | ✅ chain, emitted by all three services |
| Instant revocation | One control, whole estate, effective in seconds | ✅ kill switch; measured ~20 ms to first refusal on a laptop |

---

## 2. Trust boundaries

We verify at every boundary crossed by an untrusted party, and re-verify at the
enforcement point even though the token service already checked. Redundant
verification on the enforcement path is intentional.

| Boundary | We trust | We verify | Status |
|---|---|---|---|
| Human → Console | Nothing | OIDC signature, issuer, expiry, audience | ✅ control plane verifies all four; ⬜ web console (terminal `tools/gk.py` stands in) |
| Console → Control Plane | Nothing | Bearer token, role claims | ✅ roles reach the token and do not leak across users |
| Agent → Token Service | Nothing | Bootstrap credential hash, grant status | ✅ argon2id; grant issued to this agent, active, unexpired, unrevoked |
| Agent → PEP | Nothing | Signature, expiry, revocation, scope, policy | ✅ RS256 only, JWKS by `kid`; tampered, wrong-key, `alg: none` and expired tokens tested |
| PEP → target system | Connector credentials | TLS certificate | 🔶 mock only: connector credential held by the PEP alone; no TLS locally |
| Service → Postgres | Network isolation | — | ✅ services connect as a non-owner role (§7) |

---

## 3. Failure behaviour

**Gatekeep down means agents lose access. We fail closed.** That is the correct
default for a security product and we state it without hedging.

| Failure | Behaviour | Status |
|---|---|---|
| Control Plane down | No new grants or approvals. Existing tokens work until expiry (max 5 min), then agents stop | ✅ PEP and token service do not call it |
| Token Service down | No new or refreshed tokens. Agents drain within 5 minutes | ✅ PEP caches JWKS; ⬜ failure-injection test |
| PEP down | All agent access stops immediately | ✅ agents hold no upstream credential |
| Redis down | Fall through to Postgres. Slower, still correct | ✅ Postgres is consulted on every request anyway (DECISIONS); flush tested, ⬜ outage test |
| Postgres down | Deny everything. We cannot verify revocation, so we must not allow | ✅ code path (503); ⬜ failure-injection test |
| OpenFGA down | Deny everything. No policy decision means no access | ✅ code path (503 at PEP, approval refused); ⬜ failure-injection test |

The five-minute token lifetime is what makes this tractable: worst case, a
revoked grant remains usable for five minutes without any real-time revocation
anywhere. Because all traffic passes the PEP, actual revocation is sub-second,
and the short TTL is defence in depth for anything that bypasses the happy path.

---

## 4. Threat model

Framed with STRIDE. **[Day 8]** expands each row with the specific attack, the
control, and its test. **[Day 19]** adds the Day 22 adversarial findings.

| Threat | Primary mitigation | Status |
|---|---|---|
| Spoofing — pretending to be someone else | Signed tokens, verified issuer and audience | ✅ |
| Tampering — modifying data in transit or at rest | Signatures, hash-chained audit, TLS | ✅ audit chain and token signatures; ⬜ TLS |
| Repudiation — denying you did something | Dual identity in the token (`sub` human, `act.sub` agent) plus the audit chain | ✅ |
| Information disclosure — leaking data | Digests never bodies, minimal claims, no secrets in tokens | ✅ by construction (§6) |
| Denial of service | Rate limits, request size caps | 🔶 64 KB body cap at the PEP; ⬜ rate limits (see 8.7, 8.8) |
| **Elevation of privilege** | Invariant 1 and Invariant 2, deny-by-default at the PEP | ✅ |

Elevation of privilege is our most important class. Two invariants defend it:

- **Invariant 1** — a grant may never contain a scope the human principal does
  not themselves hold. Checked at approval time.
- **Invariant 2** — a token may never contain a scope broader than its grant.
  Checked at issuance.

Both are implemented and tested (`test_grant_cannot_exceed_principal`,
`test_token_scope_subset_of_grant`), and the PEP enforces the token's scope again
on every request. A third check closes the gap between approval and use: the PEP
asks OpenFGA whether the human *still* holds each record, so withdrawing
someone's access stops their agents too (`test_policy_denial_after_rights_withdrawn`).

---

## 5. Authorization model

Relationship-based (ReBAC) via OpenFGA, the model Google published as Zanzibar.
Chosen because per-record authority is the entire product claim, and neither
role-based nor attribute-based access control can express it without either a
role per record or an unanswerable "who can access this?" query.

Status: ✅ **implemented, seeded and verified in CI.** Four object types
(account, opportunity, invoice, note) with inheritance from the parent account.
Eleven acceptance checks run on every seed and every push; six must return
*deny*.

One property is worth naming to an auditor because it is what makes delegation
safe: **read access does not confer write access.** A user who can view an
account can view records beneath it, but writing requires ownership of the
parent. This is the single line that prevents a read-only analyst delegating
write authority to an agent, and it has a dedicated test.

---

## 6. Data handling

**We store cryptographic digests of request and response bodies. We never store
the bodies.**

This is not a preference. Storing the contents of records an agent touched would
make Gatekeep a data-breach liability and would end enterprise deals in security
review. The audit schema has a `payload_digest` column and no body column, and
§9.1 requires a test that scans audit rows for anything resembling record
content: ✅ `test_no_response_bodies_in_audit`.

Tokens are signed, not encrypted. Anyone holding a token can read every claim in
it, so tokens carry no secrets and no personal data beyond what is necessary.

Customer deployment is fully in-VPC. No record contents leave the customer's
network, because we never hold them in the first place.

---

## 7. The audit chain

Status: ✅ **implemented and tested.**

Each entry stores the SHA-256 of the previous entry's hash concatenated with
this entry's canonical form. Editing any entry breaks every entry after it, and
a verifier walking the chain names the exact break.

This gives **tamper-evidence, not tamper-proofing**. We cannot stop a database
administrator editing a row. We can guarantee it is detectable. For audit
purposes that is the property that matters, and it is what lets a customer hand
an export to a regulator.

Two implementation details a security architect will ask about:

**Concurrent writes cannot fork the chain.** Computing an entry means reading
the current last hash and then inserting. Two concurrent writers would both read
the same last hash and the chain would fork silently. A Postgres advisory lock
makes read-then-insert atomic across connections and across multiple control
plane instances. Verified by a test that fires 200 concurrent writes and
verifies the chain afterwards — and by a companion test confirming that the same
workload *without* the lock does break, so the first test is not passing by
accident.

**Append-only is enforced by the database, not by application code.** Services
connect as a role holding `SELECT` and `INSERT` on the audit table and nothing
else; `UPDATE` and `DELETE` are refused by Postgres. Application-level
enforcement is one code review away from being gone. Covered by a test that
attempts both and expects refusal.

---

## 8. Known limitations

Stated plainly. Each is something we would rather a customer heard from us.

### 8.1 Workload attestation is a bootstrap credential — SPIFFE is Phase 2

**Severity: medium. Disclosed in every demo.**

Agents register once and receive a bootstrap credential, stored hashed with
argon2id, which the token service validates at exchange time. This proves
possession of a secret; it does not cryptographically attest that the process
calling us is the workload it claims to be.

SPIFFE/SPIRE attests workloads from properties of the platform — which pod,
which node, which process — and issues short-lived identities with no static
secrets anywhere. It is deferred because it needs a trust domain design, node
attestation config, and a registration pipeline: roughly a week of a
twenty-five-day build, to prove a property no buyer asks about in a first demo.

Delegation semantics are identical either way. Only the strength of the agent's
own identity claim differs. **Say this out loud in demos rather than waiting to
be caught.**

### 8.2 Policy tuples are seeded, not synchronised

**Severity: medium. Phase 2.**

OpenFGA holds relationship facts mirrored from the system of record. For the MVP
these are seeded. In production, if ownership changes in the target system and
our tuples do not, we make wrong decisions — in both directions. Production
needs a sync job with a defined staleness bound. Not built, and not simulated.

### 8.3 The stated reason for a denial is not covered by the hash

**Severity: low. Newly identified, Day 7.**

The canonical serialisation defined in §5.4 of the engineering handbook covers
eleven fields. `reason` is stored on the row but is not among them, so the
recorded reason for a denial could be altered without breaking the chain. The
decision, the resource, the principal, the agent and the timestamp are all
covered — an attacker cannot change *what happened*, only the explanatory note
attached to it.

We follow §5.4 exactly rather than closing this locally, because verification
has to be byte-identical between writer and verifier and a local deviation would
make our exports unverifiable by anyone else's implementation. Closing it
properly means changing the canonical form, re-hashing existing entries, and a
second reviewer. Tracked, not silently patched. A test pins the current
behaviour so the gap cannot be closed by accident without updating this section.

### 8.4 Development environment is not a security boundary

**Severity: informational.**

The local stack runs Keycloak in `start-dev` (no TLS), OpenBao in dev mode
(auto-unsealed, and it loses all keys on restart), OpenFGA on the in-memory
store, and well-known credentials throughout. None of this is a production
configuration and none of it is intended to be. **[Day 19]** — the deployment
guide must state the production posture for each.

### 8.5 Single connector, and it is a mock

**Severity: informational. Scheduling, not security.**

Connector one is the mock; Salesforce is Phase 2. See
[CONNECTOR-NOTES.md](CONNECTOR-NOTES.md). This does not affect the enforcement
path, which is connector-agnostic by design.

### 8.6 Sub-agent delegation is designed for but not implemented

**Severity: informational. Phase 2.**

Nested `act` claims express an agent delegating to a sub-agent. The token format
accommodates it; nothing implements or enforces depth limits. An agent cannot
currently spawn a child that carries narrowed authority.

### 8.7 Constraints are carried, not enforced

**Severity: medium. Cut under the handbook's §8.4 order.**

Grants accept `constraints` (`max_records`, `rate_limit_rpm`) and the token
carries them, but the PEP does not yet count against them. Scope and policy are
enforced on every request; volume is not. An agent inside its scope can make as
many requests as it likes until the grant expires or is revoked.

### 8.8 Unauthenticated requests to the PEP write audit entries

**Severity: low.**

Every denial is audited, including requests with no token or a forged one - that
is deliberate, a denial with no trace is a hole in the evidence. The cost is that
anyone who can reach the PEP can grow the audit chain, and every write takes the
chain's advisory lock. Needs rate limiting in front of the PEP, or sampling of
unauthenticated denials, before exposure beyond a private network.

### 8.9 No web console yet

**Severity: informational. Scheduling.**

Approvals, sessions, the kill switch and audit search are available through the
API and the terminal client `tools/gk.py`, which logs in through Keycloak and
enforces exactly the same checks. The Keycloak `gatekeep-console` client has the
password grant enabled so that client can log in from a terminal; that is a
development convenience and must be off in any real deployment, where the
console uses authorization code with PKCE.

---

## 9. Deployment requirements

These are requirements, not recommendations. A deployment that does not meet
them is not running Gatekeep as designed.

### 9.1 Network egress control — the hard one

**Agents must have no network route to target systems except through the PEP.**

A decision point without an enforcement point in the request path is advice, not
security. If an agent can reach the target system directly, Gatekeep is a
logging product.

This is a customer-side control. We specify it, and we verify it in our own
demo environment. Be honest with customers that it is theirs to enforce.
Status: 🔶 — the mock Salesforce refuses any request without the connector
credential, which only the PEP holds, and the demo shows a direct call being
refused. That is credential isolation, not network isolation: the application
services run on the host, so Compose egress rules cannot yet be applied to them.

### 9.2 Database roles

Services must connect as `gatekeep_app`, not as the database owner. The audit
table's append-only guarantee is a Postgres grant, and a superuser bypasses
permission checks entirely. Status: ✅ role created with `SELECT`/`INSERT` only,
covered by a test.

### 9.3 Key custody

The token-signing key lives in OpenBao's transit engine and is never released.
The token service sends a payload and receives a signature; it does not hold the
private key at any point. Status: ✅ key exists, is non-exportable, and a test
confirms an export attempt is refused. **[Day 8]** — rotation procedure.

### 9.4 Identity provider

Keycloak is our development stand-in and our on-premise option. Production
federates to the customer's own provider over OIDC. Gatekeep's principal
identifier is an explicit `principal` claim rather than the provider's `sub`,
specifically so that swapping provider is a claim mapping rather than a code
change.

---

## 10. Verification and evidence

What a customer can actually hand to an auditor. **[Day 8]** expands; **[Day
14]** ships the export and the verifier CLI.

- Every authorization decision, allowed or denied, is a chain entry with a
  reason: approvals and refusals, token issuance and refusals, every PEP decision,
  revocations and the kill switch.
- `GET /v1/audit/verify` and `make audit-verify` walk the chain from genesis and
  name the first altered or missing entry. ⬜ signed export bundle (cut, §8.4).
- The chain is verifiable independently of us: given the export, the algorithm
  in §5.4 reproduces every hash.
- Application logs and the audit chain are separate and must not be conflated.
  Application logs are for engineers, may contain more detail, and may be
  deleted. Audit entries are append-only and evidentiary.

---

## 11. Reporting a vulnerability

**[Day 19]** — contact address, disclosure window, and PGP key. Not yet
established. Do not ship to a customer without this section filled in.
