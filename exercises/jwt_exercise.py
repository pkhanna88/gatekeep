"""
Appendix A comprehension item 1:
  "Decode a JWT from the token service and identify sub, act, exp, scope."

The token service does not exist until Day 6-7, so mint the section 6.3 token
yourself. Same claim shape, same lesson.

Sections 1-5 cover what Appendix A asks for. Section 6 goes one step further
and is the part worth your attention, because it explains why two of our
invariants have to live in code rather than in the token format.

    make jwt
"""

import base64
import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

NOW = int(time.time())

# The exact claim set from section 6.3.
CLAIMS = {
    "iss": "https://gatekeep.internal/token",
    "sub": "priya.sharma@acme.com",
    "act": {
        "sub": "agent://acme/invoice-reconciler",
        "instance": "run-01HQ3K9Z2P",
        "spawned_at": "2026-08-17T09:14:02Z",
    },
    "aud": "gatekeep-pep",
    "grant_id": "gr_01HQ3K8W7X",
    "purpose": "Reconcile August invoices for Northwind Traders",
    "scope": [
        "salesforce:opportunity:read:0015g00001XYZ",
        "salesforce:invoice:read:0015g00001XYZ",
        "salesforce:note:write:0015g00001XYZ",
    ],
    "constraints": {"max_records": 500, "rate_limit_rpm": 60},
    "iat": NOW,
    "exp": NOW + 300,
    "jti": "tok_01HQ3K9Z3M",
}

# Production signs with RS256 via OpenBao transit (section 3.5). Here we hold
# the key locally, which is exactly what section 3.5 says never to do in the
# real service.
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key()
token = jwt.encode(CLAIMS, key, algorithm="RS256", headers={"kid": "gk-2026-08"})


def rule(title: str) -> None:
    print("=" * 72)
    print(title)
    print("=" * 72)


def b64(part: str) -> dict:
    """Decode a JWT segment. No key involved - that is the whole point."""
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def verify(label: str, candidate: str, **kwargs) -> None:
    try:
        jwt.decode(candidate, pub, algorithms=["RS256"], audience="gatekeep-pep", **kwargs)
        print(f"  {label:34} VERIFIED")
    except jwt.PyJWTError as e:
        print(f"  {label:34} REJECTED - {type(e).__name__}")


rule("1. THE TOKEN")
print(token[:80] + "...\n")
print("Three dot-separated parts:", len(token.split(".")), "\n")

header, payload, sig = token.split(".")

rule("2. READ IT WITH NO KEY AT ALL")
print("header ", json.dumps(b64(header)))
print("payload", json.dumps(b64(payload), indent=2)[:400], "...\n")
print("Anyone holding this token can read every claim. Hence section 2.4: no")
print("secrets, no personal data beyond what is necessary. The signature")
print("protects integrity, not confidentiality.\n")

claims = b64(payload)

rule("3. THE FOUR CLAIMS APPENDIX A ASKS YOU TO IDENTIFY")
print(f"sub      {claims['sub']}")
print("         the HUMAN. Always. Never the agent.")
print(f"act.sub  {claims['act']['sub']}")
print("         the AGENT. act.instance is the session id in agent_sessions.")
print(f"exp      {claims['exp']}  ({claims['exp'] - claims['iat']}s after iat)")
print("         five minutes, per section 2.10.")
print("scope    " + "\n         ".join(claims["scope"]))
print("         system:type:action:id - resource-level, per section 5.3.\n")
print("A service-account token has act.sub and no real sub.")
print("An impersonation token has sub and no act. This has both. That pair")
print("is the entire product.\n")

rule("4. TAMPER WITH IT")
evil = dict(claims)
evil["scope"] = ["salesforce:opportunity:read:*"]
forged_payload = (
    base64.urlsafe_b64encode(json.dumps(evil, separators=(",", ":")).encode()).decode().rstrip("=")
)
verify("original", token)
verify("payload edited after signing", f"{header}.{forged_payload}.{sig}")
print("\nThe forged token is still perfectly readable. It just will not verify.")
print("That is the property the PEP relies on in section 7.2 step 1.\n")

rule("5. EXPIRY IS ENFORCED, WITH ROOM FOR CLOCK DRIFT")
stale = jwt.encode({**CLAIMS, "exp": NOW - 10}, key, algorithm="RS256")
verify("expired 10s ago", stale)
verify("same token, leeway=30", stale, leeway=30)
print("\nSection 3.3 asks for 30 seconds of leeway because container clocks")
print("drift. Without it, a valid token gets rejected and the error looks")
print("like a signature problem rather than a clock problem.\n")

rule("6. A VALID SIGNATURE IS NOT A CORRECT TOKEN")
print("Everything below is signed with OUR key, unmodified, and verifies")
print("cleanly. Watch what the signature is willing to vouch for.\n")

# The two identities swapped: the token now claims the agent is the human.
swapped = dict(CLAIMS)
swapped["sub"] = CLAIMS["act"]["sub"]
swapped["act"] = {"sub": CLAIMS["sub"]}
verify("identities swapped", jwt.encode(swapped, key, algorithm="RS256"))

# No act claim at all. This is failure mode two from Part 1: the agent is
# now indistinguishable from Priya in every downstream log.
impersonation = {k: v for k, v in CLAIMS.items() if k != "act"}
verify("act removed (impersonation)", jwt.encode(impersonation, key, algorithm="RS256"))

# A scope on an account Priya has no relationship with.
overreach = dict(CLAIMS)
overreach["scope"] = ["salesforce:opportunity:read:0015g00099ABC"]
verify("scope the principal lacks", jwt.encode(overreach, key, algorithm="RS256"))

print("""
Three tokens that should never exist. All three verify.

A signature proves two things and no others: this token was issued by the
holder of the private key, and not one byte has changed since. It says
nothing about whether the claims were true when they were written.

So nothing in the token format can stop us minting a grant wider than the
human holds, or dropping the actor and quietly becoming an impersonation
product. Only code can:

  Invariant 1  checked at approval time - a grant may never contain a scope
               the principal does not themselves hold
  Invariant 2  checked at issuance      - a token may never contain a scope
               broader than its grant

That is why both have dedicated tests, and why any change touching them
needs a second reviewer. They are not belt-and-braces. They are the only
thing standing between us and the two failure modes in Part 1.

Section 7.2 step 5 then re-checks policy at access time, because rights can
be withdrawn in the five minutes after a token was minted. Approval sets the
ceiling; the PEP enforces the present.
""")

print("Worth trying yourself: change 'aud' to something else and re-run, or")
print("sign with a second key and present it against the first public key.")
