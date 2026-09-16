# Architecture

Finalised on Day 21 with diagrams. Until then, the current build:

## What exists (Day 8)

| Component | Where | Does |
|---|---|---|
| Control plane :8000 | `services/control-plane/app` | Agent registry (argon2id bootstrap credentials), grant lifecycle, approval with Invariant 1 against OpenFGA, revoke, kill switch, audit search and verification |
| Token service :8001 | `services/token-service/token_service` | RFC 8693 exchange, Invariant 2, RS256 signing through OpenBao transit, JWKS |
| PEP proxy :8002 | `services/pep-proxy/pep_proxy` | Token verification, revocation, request-to-scope mapping, scope check, access-time OpenFGA check, forward, audit. Deny by default |
| Mock Salesforce :8003 | `services/mock-salesforce` | Connector one's upstream (docs/CONNECTOR-NOTES.md) |
| Shared | `services/control-plane/app` | settings, scopes, OpenFGA client, JWT verification, revocation, audit writes - imported by the other services |

All three services write the one audit chain directly, serialised by the
Postgres advisory lock. The PEP reads grant status from Postgres (Redis first,
for fast denials) rather than calling the control plane, so enforcement does not
depend on the control plane being up.

The step-by-step request flow, with what each check does, is in
[DEMO.md](DEMO.md) section 4. Decisions behind the shape are in
[DECISIONS.md](DECISIONS.md) under Day 8.

## Known planned evolution

The PEP Proxy is written in Python for team-fluency reasons. It is the one
component likely to be rewritten in Go or Rust if we win a high-volume deal.
It is being designed behind a clean interface so that rewrite stays contained
to one service. This is planned, not a surprise.
