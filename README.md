# Gatekeep

Agent authorization layer for the enterprise. An agent acts on behalf of a
named human, carrying a strict subset of that human's authority, for a few
minutes, with every action provable afterwards.

---

## Get running

You need Docker Desktop (running, not just installed) and Python 3.12.

```bash
git clone <repo-url> && cd gatekeep

make setup                         # one time: builds .venv, installs tools
make dev                           # start everything, wait for it to be ready
make migrate                       # apply the database schema
make seed                          # policy model, tuples, signing key
make smoke                         # confirm your machine is genuinely working
make urls                          # logins and addresses
```

**You never need to activate anything.** Every `make` target runs Python from
`.venv` explicitly. This is deliberate: if you have Anaconda, Homebrew Python,
or the system Python on your PATH, `make` will still use the right one. If you
skip `make setup`, the other targets tell you so in one line rather than
failing with a `ModuleNotFoundError` forty lines deep.

If `make setup` warns that it could not find Python 3.12, it will still work
today, but install 3.12 before service code lands (`brew install python@3.12`
on macOS). The services target 3.12 and the linter is configured for it.

`make smoke` is the one that matters. It does not just check that containers
started — it checks the identity realm actually imported, the three test users
exist, and the signing service is usable. Containers can be "up" and still
useless.

**If `make dev` or `make smoke` fails on your machine, say so in the team
channel straight away.** This is a whole-team blocker, not something to quietly
work around. Ping INF.

Run `make help` for everything else.

---

## Run the demo

With the stack up, migrated and seeded:

```bash
make services                      # terminal 1: control plane, token service, PEP, mock Salesforce
make demo PAUSE=1                  # terminal 2: the full story, each step explained
```

There is no web console yet. Every step prints what is happening in plain
English and what is happening underneath, then the real calls and results.
[docs/DEMO.md](docs/DEMO.md) is the written walkthrough, including a live
three-terminal version where you approve and kill a running agent by hand with
`make gk`.

`make test` runs the security tests in `tests/test_delegation.py` against the
running services; they skip if `make services` is not up.

---

## What is running

| Service | Address | What it does |
|---|---|---|
| Keycloak | 8080 | Logs humans in. Stands in for the customer's real login system. |
| OpenFGA | 8081 | Answers "is this person allowed to touch this record?" |
| OpenBao | 8200 | Holds the key we sign tokens with, so no service ever holds it. |
| Postgres | 5432 | Grants, agents, and the audit trail. |
| Redis | 6379 | Fast lookups for "has this been cancelled?" and rate counters. |
| Control plane | 8000 | Agents ask for permission here; humans approve, revoke, hit the kill switch, read the audit trail. `make services` |
| Token service | 8001 | Turns an approved grant into a five-minute token carrying both the human and the agent. `make services` |
| PEP proxy | 8002 | The guard. Every agent request is checked, logged, then forwarded - or refused. `make services` |
| Mock Salesforce | 8003 | Stand-in for Salesforce. Only answers the PEP. `make services` |

To build intuition for the permission model before you write policy code, use:

```bash
make fga-explain                      # walk the seeded examples
make fga-explain U=priya@acme.test R=viewer O=opportunity:0065g00001NWD
```

It prints the inheritance path the engine actually took, which is what
Appendix A asks you to be able to explain out loud.

**The built-in OpenFGA playground is disabled, and it is not a setting you
should turn back on.** It is a page that loads a remote website
(`play.fga.dev`) in a frame, and that public page then has to call the API on
your own machine. Chrome, Safari and Firefox now all block that. It cannot be
fixed from our side — the documented server-side opt-in header was tested and
every browser still refused — and it is deprecated upstream anyway. Reasoning
in `docs/DECISIONS.md`.

---

## Two things to know before you touch anything

**Everything must agree on one hostname.** Your browser reaches Keycloak at
`localhost:8080`; a container reaches it at `keycloak:8080`. Tokens carry
whichever name issued them, and checking a token minted under one name against
a service expecting the other fails in a way that looks like a broken
signature. **We use `localhost` everywhere.** Do not "fix" a connection problem
by changing a hostname in one service — you will break token validation
somewhere else. Ask first.

**Never configure Keycloak by clicking around and leaving it there.** Its
settings live inside its own database, so anything you click exists only on
your laptop and vanishes on the next `make clean`. If you change something in
the admin UI, export the realm to `deploy/keycloak-realm.json` and commit it
immediately.

---

## Layout

```
services/control-plane/   :8000  agents, grants, approvals (Invariant 1), kill switch, audit API
services/token-service/   :8001  swaps an approved grant for a 5-minute token (Invariant 2), JWKS
services/pep-proxy/       :8002  every agent request passes through here
services/mock-salesforce/ :8003  connector one's upstream; answers only the PEP
policy/                   the permission model
deploy/                   realm file and seed data
tools/demo.py             the narrated end-to-end demo
tools/gk.py               the console, in a terminal (stand-in until apps/console exists)
tools/agent.py            the demo agent: invoice reconciler for Northwind
tools/audit_verify.py     walks the audit trail and finds tampering
exercises/                onboarding exercises (Appendix A)
docs/                     architecture, security, decisions, DEMO.md
```

Not built yet: `apps/console/` (web UI) and `sdk/` - see docs/DECISIONS.md, Day 8.

---

## House rules

- **Anything unclear gets refused.** If you find yourself writing `else:
  allow`, stop and rewrite the function.
- **Never log the contents of records** the agent touched. Store a fingerprint
  of the content, never the content. Storing bodies turns us into a data-breach
  liability and kills deals.
- **A grant can never include permission the human does not personally have.**
- **A token can never be broader than the grant it came from.**
- Changes touching either of those two rules, the audit trail, or the proxy's
  refusal path need a second reviewer. Including the lead.
- Every decision worth explaining later goes in `docs/DECISIONS.md`, when you
  make it, not afterwards.

---

## Day 1 onboarding

Appendix A of the handbook. Work through it on your first morning:

```bash
make dev && make migrate && make seed   # environment
make test                               # everything, on a clean checkout
make jwt                                # look at a token
python3 exercises/fga_check.py          # then ask your own with make fga-explain
```

`make seed` prints the policy acceptance matrix as it runs. Six of the eleven
checks must come back `False` — the denials are the part that matters.

To see what exists so far as a narrative rather than test output:

```bash
make demo-week1               # identity, per-record policy, tamper-evident log
make demo-week1 PAUSE=1       # stop between beats, for showing to someone
```

It asserts every step and exits non-zero if anything misbehaves, so it is a
regression check as well as a demo. It does not cover the console, token
exchange, the PEP or the kill switch, because those do not exist yet.
