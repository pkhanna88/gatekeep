# Security — honest limitations

Skeleton (INF, Day 5). First real draft Day 8. Completed Day 19.
Becomes sales collateral, so write it for a CISO, not for us.

## Known gaps

- **Workload attestation.** Agents authenticate with a bootstrap credential
  validated at token exchange. Cryptographic attestation via SPIFFE/SPIRE is
  Phase 2. State this out loud in demos rather than waiting to be caught.

## Deployment requirements

- Agents must have no network route to target systems except through the PEP.
  This is a requirement, not a recommendation.
