# Decision log

Every significant decision, recorded when it is made. New joiners and
occasionally customers need the reasoning.

| Date | Decision | Reasoning | Revisit when |
|---|---|---|---|
| Prebuild | Python over Go | Team fluency; four engineers learning identity should not also learn a language | High-volume deal needs sub-10ms |
| Prebuild | SPIRE deferred | ~1 week of 25; no first-demo buyer asks for attestation | Phase 2, or first customer who asks |
| Prebuild | ReBAC via OpenFGA | Only model that expresses per-record authority without role explosion | Never — this is core |
| Prebuild | 5-minute token TTL | Makes revocation tractable; defence in depth beyond the PEP | If refresh traffic becomes a bottleneck |
| Prebuild | Salesforce as connector one | Recognisable to buyers; free dev org | Day 2 gate if spike overruns |
| Prebuild | Advisory lock on audit writes | Prevents chain forking under concurrency; survives multiple instances | If audit write throughput becomes a bottleneck |
| Day 1 | Hostname is `localhost` everywhere | See README. Browser and containers must agree on one name or token validation fails | If we deploy anywhere but a laptop |
| Day 1 | OpenFGA uses the in-memory store | Skips a migration step; `make seed` is the source of truth anyway | When tuples need to survive a restart |
