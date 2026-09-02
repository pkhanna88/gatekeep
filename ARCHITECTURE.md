# Architecture

Placeholder. Finalised on Day 21 with diagrams.

## Known planned evolution

The PEP Proxy is written in Python for team-fluency reasons. It is the one
component likely to be rewritten in Go or Rust if we win a high-volume deal.
It is being designed behind a clean interface so that rewrite stays contained
to one service. This is planned, not a surprise.
