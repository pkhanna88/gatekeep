# Connector notes

## Decision

**Connector one is the mock. Salesforce moves to Phase 2.**

Decided 2026-09-09 by INF, on the Day 2 decision gate. Recorded in
[DECISIONS.md](DECISIONS.md).

## Why, honestly

The handbook frames this gate as a schedule-risk call: if the Salesforce spike
looks likely to exceed four days, connector one becomes the mock.

That is not quite the situation we are in. **The spike was never started.** BE2
was unstaffed through Days 1–7 and no Salesforce developer org, connected app,
or authenticated REST call exists. So we are not choosing the mock because the
spike overran — we are choosing it because there is no evidence, and the gate
exists precisely so that the absence of evidence is decisive early rather than
expensive later:

> Making that call on Day 2 costs nothing. Making it on Day 15 sinks the
> delivery. (§3.12)

Deciding today costs a demo prop. Deciding on Day 15 costs the delivery. With
the spike unstarted on Day 7, the four-day estimate has already become at best
a four-day estimate *starting from zero*, against a Week 3 deadline for
"Salesforce behind the PEP" (Day 13) that also depends on the PEP existing.

## The three questions, unanswered

The template asks these explicitly. None has been established by our own
testing, and nothing below should be quoted to a customer as our finding.

| Question | Status |
|---|---|
| Can we proxy Salesforce REST cleanly? | **Not established.** No request has been made. |
| What does the OAuth setup require? | **Not established.** §3.12 warns the connected app has "several non-obvious settings"; we have not confirmed which. |
| What are the rate limits? | **Not established.** §3.12 warns they "will bite during load testing." Not measured. |

Phase 2 starts by answering these three, not by writing connector code.

## What this does and does not cost

**Does not cost:** the product. §8.4 lists the Salesforce connector as the
second thing to cut and never as a thing to protect. The five never-cut items —
delegation semantics, Invariant 1, Invariant 2, the audit chain, deny-by-default
at the PEP, and the kill switch — are all connector-agnostic. Week 2's exit
criteria say it outright:

> The delegation story is the product. Salesforce is a demo prop.

**Does cost:** demo realism. §3.12 is right that "a demo against Salesforce
reads as real in a way that a demo against a mock does not." We should expect
a buyer to ask, and answer it directly rather than hoping it does not come up:
the enforcement path is identical, Salesforce is one implementation of a
`Connector` behind an interface, and the mock exercises every step of the
pipeline the real one would.

## What has to be true for this to stay a cheap decision

§3.12's actual architectural point is not about Salesforce at all:

> The connector interface is what actually matters architecturally. Salesforce
> is one implementation of it; the mock is another. Keeping that boundary clean
> is what makes SAP and ServiceNow tractable later.

So the mock is only a safe choice if it is built **against the interface**, not
instead of one. Specifically, the mock must not become a shortcut that lets the
PEP skip steps:

- It implements the same `Connector` protocol Salesforce would (§3.12 gives the
  shape: `name`, `map_request`, `forward`).
- `map_request` produces real resource-level actions —
  `salesforce:opportunity:read:0065g00001NWD` — not a coarse
  `salesforce:read:*`. §5.3 is explicit that a coarse-scoped demo is
  indistinguishable from an API gateway.
- The objects it serves match the seeded policy tuples, so a denial in the demo
  is a genuine policy denial rather than a missing fixture. The seed data in
  `deploy/seed/fga-tuples.json` already provides both halves: Northwind
  (`0015g00001XYZ`, Priya owns it) and Contoso (`0015g00099ABC`, nobody holds
  anything on it).

**Owner: BE2, Day 3** — "Define the Connector protocol; implement the mock
against it." That task is unchanged by this decision; only its second
implementation is deferred.

## Revisit when

- A named buyer asks for a live Salesforce demo before Phase 2, **or**
- BE2 is staffed and Week 2 exit criteria are met early, leaving genuine slack.

Revisit by running the spike and answering the three questions above — not by
reopening the decision in the abstract.
