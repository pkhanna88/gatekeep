"""
The Week 1 demo, in the parts INF owns.

    make demo-week1              run it
    make demo-week1 PAUSE=1      stop between beats, for showing to someone

Section 10.1 is an eight-minute narrative and most of it needs the control
plane, the token service and the console. This is the half that exists today:
who Priya is, what she may touch, and whether the evidence holds up afterwards.

Beat 5 is the one worth slowing down for. Section 10.1 calls it the strongest
single moment in the sales demo - corrupt a row in front of the customer, run
the verifier, watch it name the exact broken entry.

This is not theatre. Every assertion is real and the script exits non-zero if
anything fails to behave, so it cannot quietly become a slideshow.
"""

import argparse
import asyncio
import base64
import json
import os
import pathlib
import sys

import asyncpg
import httpx

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "services" / "control-plane")
)
from app import audit  # noqa: E402

KEYCLOAK = "http://localhost:8080"
OPENFGA = "http://localhost:8081"
OWNER_DSN = "postgres://gatekeep:gatekeep@localhost:5432/gatekeep"
APP_DSN = "postgres://gatekeep_app:gatekeep_app@localhost:5432/gatekeep"

NO_COLOR = bool(os.environ.get("NO_COLOR"))


def c(code: str, s: str) -> str:
    return s if NO_COLOR else f"\033[{code}m{s}\033[0m"


def green(s):
    return c("32", s)


def red(s):
    return c("31", s)


def bold(s):
    return c("1", s)


def dim(s):
    return c("2", s)


PAUSE = False


def beat(n: int, title: str, subtitle: str = "") -> None:
    if PAUSE:
        input(dim("\n    [enter]"))
    print("\n" + bold("=" * 76))
    print(bold(f"  {n}. {title}"))
    if subtitle:
        print(dim(f"     {subtitle}"))
    print(bold("=" * 76) + "\n")


failures: list[str] = []


def check(ok: bool, msg: str) -> None:
    if not ok:
        failures.append(msg)
        print(red(f"  UNEXPECTED: {msg}"))


# --------------------------------------------------------------------------


def beat_1_who_is_priya() -> None:
    beat(1, "Priya logs in", "Her real identity provider. We never see a password.")

    r = httpx.post(
        f"{KEYCLOAK}/realms/gatekeep/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "gatekeep-console",
            "username": "priya@acme.test",
            "password": "priya",
            "scope": "openid",
        },
        timeout=10,
    )
    check(r.status_code == 200, f"Keycloak returned {r.status_code}")
    p = r.json()["access_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))

    print(f"  principal   {green(claims.get('principal', 'MISSING'))}")
    print(dim("              What every permission and every audit row keys off."))
    print(f"  sub         {dim(claims['sub'])}")
    print(dim("              The provider's own id. Opaque on purpose, so swapping"))
    print(dim("              Keycloak for Okta is a claim mapping, not a rewrite."))
    print(f"  aud         {claims.get('aud', 'MISSING')}")
    print(f"  roles       {claims['realm_access']['roles']}")
    print(f"  expires in  {claims['exp'] - claims['iat']}s")

    check("principal" in claims, "no principal claim")
    check(claims.get("aud") == "gatekeep-control-plane", "wrong audience")


def beat_2_what_may_she_touch() -> None:
    beat(
        2,
        "What Priya may touch",
        "Per record, not per application. This is the part an API gateway cannot do.",
    )

    stores = httpx.get(f"{OPENFGA}/stores", timeout=10).json()["stores"]
    store = next(s for s in stores if s["name"] == "gatekeep")["id"]
    models = httpx.get(f"{OPENFGA}/stores/{store}/authorization-models", timeout=10).json()
    model_id = models["authorization_models"][0]["id"]

    def ask(user: str, relation: str, obj: str) -> bool:
        r = httpx.post(
            f"{OPENFGA}/stores/{store}/check",
            json={
                "tuple_key": {"user": f"user:{user}", "relation": relation, "object": obj},
                "authorization_model_id": model_id,
            },
            timeout=10,
        )
        return r.json().get("allowed", False)

    rows = [
        (
            "priya@acme.test",
            "viewer",
            "opportunity:0065g00001NWD",
            True,
            "Northwind — she owns the account",
        ),
        (
            "priya@acme.test",
            "editor",
            "note:0NOT00001NWD",
            True,
            "may write the reconciliation note",
        ),
        (
            "priya@acme.test",
            "viewer",
            "opportunity:0065g00099CTO",
            False,
            "Contoso — no relationship at all",
        ),
        (
            "auditor@acme.test",
            "viewer",
            "opportunity:0065g00001NWD",
            True,
            "read-only user can read",
        ),
        (
            "auditor@acme.test",
            "editor",
            "note:0NOT00001NWD",
            False,
            "...and cannot write. This is the line",
        ),
    ]
    for user, rel, obj, expect, why in rows:
        got = ask(user, rel, obj)
        check(got == expect, f"{user} {rel} {obj} returned {got}")
        mark = green("ALLOW") if got else red(" DENY")
        print(f"  {mark}  {user:20} {rel:7} {obj:26}")
        print(dim(f"         {why}"))

    print()
    print(dim("  Priya holds no direct permission on that opportunity. The ALLOW is"))
    print(dim("  inherited: opportunity -> parent account -> she owns it. Two facts."))
    print(dim("  Role-based access would have needed a role per account to say it."))
    print()
    print(bold("  The last two rows are the important ones. Being able to READ an"))
    print(bold("  account does not let you WRITE things under it - which is what"))
    print(bold("  stops a read-only analyst handing an agent write authority."))


async def beat_3_the_agent_works(conn) -> list[dict]:
    beat(
        3,
        "The agent does its job",
        "Every decision, allowed or denied, becomes a chained audit entry.",
    )

    await conn.execute("TRUNCATE audit_events RESTART IDENTITY")

    story = [
        ("grant.requested", None, None, "allow", None, "Agent asks to reconcile August invoices"),
        (
            "grant.approved",
            None,
            None,
            "allow",
            None,
            "Priya approves. She is delegating her own authority",
        ),
        ("token.issued", None, None, "allow", None, "Five-minute token: sub=Priya, act=the agent"),
        (
            "access.allowed",
            "opportunity:0065g00001NWD",
            "read",
            "allow",
            None,
            "Reads a Northwind opportunity",
        ),
        (
            "access.allowed",
            "invoice:0INV00001NWD",
            "read",
            "allow",
            None,
            "Reads a Northwind invoice",
        ),
        (
            "access.denied",
            "opportunity:0065g00099CTO",
            "read",
            "deny",
            "policy_denied",
            "Tries Contoso. Refused",
        ),
        (
            "access.allowed",
            "note:0NOT00001NWD",
            "write",
            "allow",
            None,
            "Writes the reconciliation note",
        ),
    ]

    for event_type, resource, action, decision, reason, narrative in story:
        row = await audit.append(
            conn,
            event_type=event_type,
            principal_sub="priya@acme.test",
            agent_id="agent://acme/invoice-reconciler",
            session_id="run-01HQ3K9Z2P",
            grant_id="gr_01HQ3K8W7X",
            resource=resource,
            action=action,
            decision=decision,
            reason=reason,
            payload_digest=("d" * 64) if action else None,
        )
        mark = green("allow") if decision == "allow" else red(" deny")
        print(f"  {row['seq']:>2}  {mark}  {event_type:16} {dim(row['entry_hash'][:16] + '...')}")
        print(dim(f"        {narrative}"))

    print()
    print(dim("  Note what is NOT stored: no record contents, only a SHA-256 digest."))
    print(dim("  Storing bodies would make us a breach liability."))
    return await audit.fetch_chain(conn)


async def beat_4_evidence_holds(conn) -> None:
    beat(4, "The auditor checks the log", "Each entry carries the hash of the one before it.")
    result = audit.verify_chain(await audit.fetch_chain(conn))
    check(result.valid, "chain should be intact")
    print(f"  {green('CHAIN INTACT')}   {result.entries_verified} entries verified")
    print()
    print(dim("  Reproducible by anyone holding the export and the algorithm."))
    print(dim("  They do not have to trust us, or even run our code."))


async def beat_5_someone_edits_the_log(conn) -> None:
    beat(
        5,
        "Someone edits the database directly",
        "The most valuable minute in the demo. Do not rush it.",
    )

    before = await conn.fetchrow("SELECT seq, decision, resource FROM audit_events WHERE seq = 6")
    print("  Entry 6 today:")
    print(f"      {before['resource']}  decision={red(before['decision'])}")
    print()
    print(dim("  A denial is inconvenient. Someone with database access makes it"))
    print(dim("  look like it never happened:"))
    print()
    print(dim("      UPDATE audit_events SET decision = 'allow' WHERE seq = 6;"))

    await conn.execute("UPDATE audit_events SET decision = 'allow' WHERE seq = 6")

    after = await conn.fetchrow("SELECT seq, decision FROM audit_events WHERE seq = 6")
    print()
    normal = dim("the row looks perfectly normal")
    print(f"  Entry 6 now:  decision={green(after['decision'])}   {normal}")
    print()

    result = audit.verify_chain(await audit.fetch_chain(conn))
    check(not result.valid, "verifier failed to detect the edit")
    check(result.broken_at_seq == 6, f"named entry {result.broken_at_seq}, expected 6")

    print(f"  {red('CHAIN BROKEN')}   {result.message}")
    print(f"  {dim(f'Entries 1 to {result.entries_verified} still verify. The break is exact.')}")
    print()
    print(bold("  That is what you hand a regulator."))
    print()
    print(dim("  To be precise about the claim: this is tamper-EVIDENCE, not"))
    print(dim("  tamper-proofing. We cannot stop a database administrator editing"))
    print(dim("  a row. We guarantee it cannot be done quietly."))


async def beat_6_who_could_do_that() -> None:
    beat(6, "Could the application have done that?", "No. And that is enforced by Postgres.")

    conn = await asyncpg.connect(APP_DSN)
    try:
        print(dim("  Connecting as gatekeep_app - the role the services actually use."))
        print()
        try:
            await conn.execute("UPDATE audit_events SET decision = 'allow'")
            check(False, "gatekeep_app was allowed to UPDATE")
        except asyncpg.InsufficientPrivilegeError:
            print(f"  UPDATE audit_events  ->  {green('refused by the database')}")
        try:
            await conn.execute("DELETE FROM audit_events")
            check(False, "gatekeep_app was allowed to DELETE")
        except asyncpg.InsufficientPrivilegeError:
            print(f"  DELETE audit_events  ->  {green('refused by the database')}")
    finally:
        await conn.close()

    print()
    print(dim("  The edit in beat 5 needed a database administrator, not a bug in"))
    print(dim("  our code. Append-only is a Postgres grant, not a code review."))


async def main() -> int:
    print()
    print(bold("  GATEKEEP — Week 1 demo (the parts that exist today)"))
    print(dim("  Delegation, per-record authority, and evidence that survives contact"))
    print(dim("  with someone who wants it to say something else."))

    beat_1_who_is_priya()
    beat_2_what_may_she_touch()

    conn = await asyncpg.connect(OWNER_DSN)
    try:
        await beat_3_the_agent_works(conn)
        await beat_4_evidence_holds(conn)
        await beat_5_someone_edits_the_log(conn)
    finally:
        await conn.close()
    await beat_6_who_could_do_that()

    print("\n" + bold("=" * 76))
    if failures:
        print(red(f"  {len(failures)} step(s) did not behave as expected:"))
        for f in failures:
            print(red(f"    - {f}"))
        print(bold("=" * 76) + "\n")
        return 1
    print(green("  Every step behaved as expected."))
    print(dim("  Not yet shown, because they do not exist: the approval console,"))
    print(dim("  token exchange, the PEP, and the kill switch."))
    print(bold("=" * 76) + "\n")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pause", action="store_true", help="stop between beats")
    args = ap.parse_args()
    PAUSE = args.pause
    try:
        sys.exit(asyncio.run(main()))
    except (httpx.ConnectError, OSError) as e:
        print(f"\n  Cannot reach a dependency: {e}")
        print("  Is the stack up and seeded?   make dev && make migrate && make seed\n")
        sys.exit(2)
