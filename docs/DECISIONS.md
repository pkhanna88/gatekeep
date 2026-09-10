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
| Day 1 | OpenFGA pinned to v1.14.0 | `latest` changes under us. v1.14.0 is also the first release fixing CVE-2026-40293 (playground leaked a preshared key in HTML). We do not use preshared auth so were not exposed, but pin to a patched floor anyway | Bump deliberately; check the changelog first |
| Day 1 | ~~Playground bound to 0.0.0.0~~ | Superseded — see the playground row below. The binding was correct; the tool is not usable regardless | — |
| Day 1 fix | The principal identifier is the `principal` claim, never `sub` | Keycloak's `sub` is an opaque UUID, but every FGA tuple, `grants.principal_sub` and the §6.3 token are written as emails, so §7.1's approver check could never have matched — it would have read as a policy bug rather than a realm one. Forcing `sub` to the email fixes it locally and breaks §3.3's promise that swapping to Okta or Entra is configuration, not code, since their `sub` is a UUID too. A dedicated claim means changing IdP is remapping one field | Never, unless a customer IdP cannot mint a custom claim |
| Day 1 fix | Console tokens carry `aud: gatekeep-control-plane` | §4.4 lists audience as something we verify at the Human → Console boundary, and tokens were arriving with no `aud` at all. BE1 cannot gate approvals on a claim that is not there | When a second API starts accepting human tokens |
| Day 1 fix | OpenFGA listens on 8081/8082 inside the container, matching the published ports | OpenFGA advertises its own address to clients, derived from the port it listens on **inside** the container. The mapping `8081:8080` therefore told browsers to call `127.0.0.1:8080` — Keycloak on the host. Keeping inside and outside identical means anything OpenFGA says about where to reach it is also true from the host | If the handbook's §3.10 port assignments change |
| Day 1 fix | Built-in OpenFGA playground disabled | It is a page wrapping an iframe to the remote site play.fga.dev, and every browser now blocks a public page from reaching the loopback address space — verified on Chrome, WebKit and Firefox. Not fixable from our side: a proxy sending the documented opt-in header `Access-Control-Allow-Private-Network: true` was tested and all three still refused, so browsers have moved past header-based opt-in to blocking outright. It is deprecated upstream and hands the API token to a third party in a URL. No other role's work changes this | If OpenFGA ships a first-party local playground |
