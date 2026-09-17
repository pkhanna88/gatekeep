# Signing key rotation

**Owner: INF. Day 6.** Section 3.5: *"Plan rotation on Day 6, not later.
Retrofitting `kid`-based key selection into a working system is unpleasant."*

Two audiences. An engineer who has to rotate the key, and an auditor who wants
to know we can. Section 10 answers the auditor directly.

Every command below is against the local dev stack. Production differs in one
respect only — authentication to OpenBao — and that is called out in section 9.

---

## 1. The design, in one paragraph

Agent tokens are signed by an RSA key held in OpenBao's transit engine. The
token service never possesses that key; it sends a payload and receives a
signature. Transit versions keys: rotating creates version N+1 while keeping
every earlier version able to verify. A token's `kid` header **is** the version
it was signed with, written out — `gk-signing-v2` means transit key version 2.
JWKS publishes every live version. That is the whole scheme, and it is why
rotation needs no coordination with anything.

---

## 2. Why rotating is cheap for us

Agent tokens live **five minutes** (§2.10). So:

- At the moment you rotate, tokens signed under the old key are still in flight.
- They keep verifying, because the old version is still published in JWKS.
- Five minutes later, none exist. Nothing was drained, nothing was dual-written,
  nothing went down.

The expensive version of this problem — coordinate a cutover across every
verifier — is one we do not have, and the short TTL is the reason.

---

## 3. Routine rotation

### 3.1 Check where you are

```bash
curl -s -H "X-Vault-Token: root" \
  http://localhost:8200/v1/transit/keys/gk-signing \
  | python3 -c "import sys,json; d=json.load(sys.stdin)['data']; \
print('versions', sorted(d['keys'],key=int), 'latest', d['latest_version'], \
'floor', d['min_decryption_version'])"
```

### 3.2 Rotate

```bash
curl -s -X POST -H "X-Vault-Token: root" \
  http://localhost:8200/v1/transit/keys/gk-signing/rotate -d '{}'
```

That is the entire operation. New tokens immediately carry `kid`
`gk-signing-v<new>`; nothing else changes.

### 3.3 Expect a brief window of refusals

Verifiers cache JWKS and refetch when they meet a `kid` they do not recognise,
but that refetch is rate limited - the PEP allows at most one every 10 seconds,
so a forged `kid` cannot be used to hammer the token service. The consequence is
that for up to ten seconds after a rotation, tokens signed with the new key are
refused with `unknown_signing_key` and a 401.

That is correct behaviour, not a bug, and it is small because agent tokens live
five minutes and are re-requested constantly. But it means:

- **Do not rotate in the minute before a demo.** Ten seconds of 401s during the
  narrative is not worth the risk.
- **Never rotate the live key from a test.** `tests/test_key_rotation.py` creates
  and destroys its own throwaway key for exactly this reason - an earlier
  version rotated `gk-signing` and broke every demo run that followed it inside
  the cache window.

### 3.4 Verify before you walk away

```bash
make test-rotation
```

That runs `tests/test_key_rotation.py`, which mints a token, rotates, and
asserts the pre-rotation token still verifies against its own `kid` and does
*not* verify against the new one. If that passes, the rotation is sound.

Also confirm JWKS is publishing both:

```bash
curl -s http://localhost:8001/.well-known/jwks.json | python3 -m json.tool
```

Expect one entry per live version, each with a distinct `kid`.

---

## 4. Cadence

- **Routine: every 90 days.** Frequent enough that the procedure stays exercised,
  infrequent enough that nobody starts skipping it.
- **On any staff change with OpenBao access.** Rotation is cheap; an unrotated
  key after an offboarding is the finding an auditor will write up.
- **Immediately on suspected compromise.** See section 5.

Rotation being boring is the goal. A procedure only run during an incident is a
procedure nobody can execute during an incident.

---

## 5. Emergency: suspected key compromise

Rotating alone is **not sufficient**. Rotation stops new tokens being signed
with the old key; it does nothing about tokens an attacker already minted with
it, because the old version is still published and still verifies.

To invalidate everything signed under earlier versions, raise the floor:

```bash
# 1. Rotate first, so there is a clean key to move to.
curl -s -X POST -H "X-Vault-Token: root" \
  http://localhost:8200/v1/transit/keys/gk-signing/rotate -d '{}'

# 2. Archive every version below the new one.
curl -s -X POST -H "X-Vault-Token: root" -H "Content-Type: application/json" \
  http://localhost:8200/v1/transit/keys/gk-signing/config \
  -d '{"min_decryption_version": <NEW_LATEST>}'
```

Effect, verified: archived versions disappear from the key listing, our JWKS
stops publishing them, and every token signed under them fails verification at
once.

**This is a blast radius, not a scalpel.** Every agent in the estate loses
access immediately, including ones doing legitimate work. It is the right call
for a compromised key and the wrong call for almost anything else. For revoking
one agent or one grant, use revocation — that is what it is for.

Pair it with the kill switch (§Day 16) so grants are revoked as well as tokens
invalidated. Otherwise agents re-request tokens and carry on.

---

## 6. Rollback

Raising the floor is **reversible**, as long as the key itself has not been
deleted — OpenBao retains archived material and simply stops serving it.

```bash
curl -s -X POST -H "X-Vault-Token: root" -H "Content-Type: application/json" \
  http://localhost:8200/v1/transit/keys/gk-signing/config \
  -d '{"min_decryption_version": 1}'
```

Archived versions reappear in the listing and in JWKS.

There is no rollback for a rotation itself, and none is needed — the old version
keeps working. If a rotation appears to have broken something, the fault is
almost certainly a verifier caching JWKS and not re-fetching on an unknown
`kid`. Check that before touching the key.

---

## 7. What not to do

- **Do not fetch the key and sign locally.** §3.5 says this defeats the purpose
  entirely. The key is deliberately non-exportable and there is a test that
  attempts an export and expects to be refused.
- **Do not make the key exportable** "temporarily" to debug something. That
  turns transit into an expensive environment variable.
- **Do not delete old key versions** to tidy up. Archiving via
  `min_decryption_version` is reversible; deletion is not, and it permanently
  destroys the ability to verify anything historic.
- **Do not invent a `kid` scheme.** It is mechanically the transit version. Any
  separate mapping is a thing that can drift out of sync, and it will.
- **Do not rotate to fix a verification failure** you do not understand. Rotation
  changes what new tokens look like; it does not repair a broken verifier.

---

## 8. If a verifier rejects a valid token

In order of likelihood:

1. **Stale JWKS cache.** The verifier has a `kid` it has never seen and has not
   re-fetched yet. Verifiers re-fetch on unknown `kid`, once, with a rate limit -
   see section 3.3. If the rotation was within the last ten seconds, wait and
   retry before investigating anything else.
2. **Clock skew.** §3.3 asks for 30 seconds of leeway. Without it a valid token
   is rejected and the error looks like a signature problem rather than a clock
   problem.
3. **Signature encoding.** Transit returns `vault:v<n>:<standard base64>`; a JWT
   needs raw base64url with no padding. A token that skipped that conversion
   looks perfectly well-formed and fails every verification.
4. **Archived version.** Someone raised `min_decryption_version`. Check section 5
   before assuming a bug.

---

## 9. Production differences

Exactly one thing changes: **authentication**.

Dev runs OpenBao with a root token of `root`, auto-unsealed, and loses every key
on restart. Production requires:

- A real auth method for the token service — AppRole or Kubernetes auth — scoped
  to `transit/sign/gk-signing` and `transit/keys/gk-signing` (read) and nothing
  else. It must not hold a token that can rotate or reconfigure the key.
- **Separation of duties**: signing and rotating are different privileges. The
  service signs. An operator rotates. The same credential must never do both.
- A documented unseal procedure. OpenBao starts sealed and unsealing needs
  threshold key shares held by different people.
- Audit logging enabled on OpenBao itself, separate from our audit chain.

**[Day 19]** — the deployment guide must specify the exact policy documents.
Not yet written.

---

## 10. What an auditor will ask

**"Can you rotate the signing key?"**
Yes. One API call, roughly 90 days, and there is a test that proves a rotation
does not invalidate tokens already in flight.

**"Who can access the private key?"**
Nobody, including us. It is generated inside OpenBao's transit engine and marked
non-exportable. Our services send a payload and receive a signature. A test in
CI attempts an export on every run and expects to be refused.

**"What happens to tokens signed with the old key?"**
They keep verifying until they expire, which is at most five minutes, because
JWKS publishes every live key version and each token names the version it was
signed with.

**"How would you respond to a suspected key compromise?"**
Rotate, then raise the decryption floor so everything signed under earlier
versions fails immediately, then trigger the kill switch so agents cannot simply
request new tokens. Section 5. It is deliberately a large blast radius.

**"How do you know any of this works?"**
`tests/test_key_rotation.py` runs on every push. It rotates a real key and
asserts the exact properties described above.
