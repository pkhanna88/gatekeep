"""
Day 4/5 acceptance for the audit chain.

Section 9.1 makes three of these mandatory:

    test_canonical_serialisation_is_stable    same event serialises identically
    test_audit_chain_detects_tampering        the hash chain does its job
    test_audit_chain_under_concurrency        200 concurrent writes, chain valid

The concurrency one is the reason the advisory lock exists, and section 3.6 is
blunt about the payoff: "If it passes, this class of bug is closed permanently."

A fourth is added here because section 5.1's append-only REVOKE was decoration
until now - it named a role, gatekeep_app, that did not exist, and revoking from
the superuser services actually connect as accomplishes nothing.

These tests own the audit table and truncate it. The dev database is disposable;
`make migrate` rebuilds it.
"""

import asyncio
from datetime import UTC, datetime

import asyncpg
import pytest
from app import audit

OWNER_DSN = "postgres://gatekeep:gatekeep@localhost:5432/gatekeep"
APP_DSN = "postgres://gatekeep_app:gatekeep_app@localhost:5432/gatekeep"

NOT_MIGRATED = "audit_events does not exist. Run `make migrate`."


async def _table_exists(conn) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name='audit_events'"
        )
    )


@pytest.fixture
async def conn():
    """Owner connection, with the chain truncated so results are deterministic."""
    assert "localhost" in OWNER_DSN, "refusing to truncate a non-local database"
    try:
        c = await asyncpg.connect(OWNER_DSN)
    except OSError:
        pytest.skip("Postgres is not reachable")
    if not await _table_exists(c):
        await c.close()
        pytest.skip(NOT_MIGRATED)
    await c.execute("TRUNCATE audit_events RESTART IDENTITY")
    try:
        yield c
    finally:
        await c.close()


# --- canonical serialisation ------------------------------------------------


def _event(**over):
    base = {
        "seq": 1,
        "ts": datetime(2026, 8, 17, 9, 14, 2, 123456, tzinfo=UTC),
        "event_type": "access.allowed",
        "principal_sub": "priya@acme.test",
        "agent_id": "agent://acme/invoice-reconciler",
        "session_id": "run-01HQ3K9Z2P",
        "grant_id": "gr_01HQ3K8W7X",
        "resource": "opportunity:0065g00001NWD",
        "action": "read",
        "decision": "allow",
        "payload_digest": "a" * 64,
    }
    base.update(over)
    return base


def test_canonical_serialisation_is_stable():
    """Section 5.4 asks for exactly this test. sort_keys and fixed separators are
    load-bearing: if writer and verifier disagree by one byte, every entry in the
    chain reads as tampered."""
    e = _event()
    assert audit.compute_entry_hash(audit.GENESIS, e) == audit.compute_entry_hash(audit.GENESIS, e)


def test_serialisation_ignores_dict_ordering():
    """Python dicts preserve insertion order, so an event built in a different
    order must still hash the same or verification depends on construction."""
    a = _event()
    b = dict(reversed(list(a.items())))
    assert audit.compute_entry_hash(audit.GENESIS, a) == audit.compute_entry_hash(audit.GENESIS, b)


def test_absent_field_hashes_as_explicit_none():
    """Why CANONICAL_FIELDS is a fixed list rather than derived from the event."""
    absent = _event()
    del absent["resource"]
    explicit = _event(resource=None)
    assert audit.compute_entry_hash(audit.GENESIS, absent) == audit.compute_entry_hash(
        audit.GENESIS, explicit
    )


@pytest.mark.parametrize("field", audit.CANONICAL_FIELDS)
def test_every_canonical_field_affects_the_hash(field):
    """If a field can change without changing the hash, it is not protected -
    which is the whole claim we make to an auditor."""
    base = _event()
    changed = _event(**{field: 999 if field == "seq" else "TAMPERED"})
    assert audit.compute_entry_hash(audit.GENESIS, base) != audit.compute_entry_hash(
        audit.GENESIS, changed
    ), f"{field} is in CANONICAL_FIELDS but does not affect the hash"


def test_reason_is_not_covered_by_the_hash():
    """Pins a KNOWN GAP rather than asserting a good property.

    Section 5.4's canonical form omits `reason`, so the stated reason for a
    denial can be edited without breaking the chain. We follow 5.4 exactly
    because interoperable verification matters more than closing this locally,
    and changing the canonical form needs a second reviewer plus a plan for
    re-hashing existing entries. Recorded in docs/SECURITY.md.

    If someone closes the gap, this test fails and points at the doc.
    """
    assert "reason" not in audit.CANONICAL_FIELDS
    a = audit.compute_entry_hash(audit.GENESIS, {**_event(), "reason": "policy_denied"})
    b = audit.compute_entry_hash(audit.GENESIS, {**_event(), "reason": "anything_else"})
    assert a == b, "reason now affects the hash - update docs/SECURITY.md known gaps"


# --- the chain -------------------------------------------------------------


async def test_first_entry_chains_from_genesis(conn):
    row = await audit.append(conn, event_type="grant.requested", decision="allow")
    assert row["prev_hash"] == audit.GENESIS
    assert audit.verify_chain(await audit.fetch_chain(conn)).valid


async def test_chain_verifies_over_many_entries(conn):
    for i in range(25):
        await audit.append(conn, event_type="access.allowed", decision="allow", session_id=f"r{i}")
    result = audit.verify_chain(await audit.fetch_chain(conn))
    assert result.valid, str(result)
    assert result.entries_verified == 25


async def test_audit_chain_detects_tampering(conn):
    """Section 9.1. The demo moment in section 10.1 step 8: corrupt one row in
    front of the customer and watch the verifier name the exact entry."""
    for i in range(10):
        await audit.append(
            conn, event_type="access.allowed", decision="allow", resource=f"opportunity:{i}"
        )
    assert audit.verify_chain(await audit.fetch_chain(conn)).valid

    # Exactly what a DBA with write access could do. Note this connection is the
    # OWNER - gatekeep_app is refused, see test_app_role_cannot_rewrite_history.
    await conn.execute("UPDATE audit_events SET decision = 'allow' WHERE seq = 5")
    await conn.execute("UPDATE audit_events SET resource = 'opportunity:HIDDEN' WHERE seq = 5")

    result = audit.verify_chain(await audit.fetch_chain(conn))
    assert not result.valid, "The verifier did not notice an edited row"
    assert result.broken_at_seq == 5, f"Named entry {result.broken_at_seq}, expected 5"
    assert "edited" in result.message
    assert result.entries_verified == 4, "Everything before the break should verify"


async def test_verifier_detects_a_deleted_entry(conn):
    """A gap is a different failure from an edit, and the report should say so."""
    for i in range(6):
        await audit.append(conn, event_type="access.allowed", decision="allow", session_id=f"r{i}")
    await conn.execute("DELETE FROM audit_events WHERE seq = 3")

    result = audit.verify_chain(await audit.fetch_chain(conn))
    assert not result.valid
    assert result.broken_at_seq == 4
    assert "removed or reordered" in result.message


# --- concurrency, which is what the advisory lock is for --------------------


CONCURRENT_WRITES = 200


async def test_audit_chain_under_concurrency(conn):
    """Section 9.1 and section 3.6: fire 200 concurrent audit writes and verify
    the chain afterwards.

    Without the lock, two writers read the same last hash and both claim to
    follow it. The chain forks silently and nothing surfaces until a verifier
    runs weeks later.
    """
    pool = await asyncpg.create_pool(OWNER_DSN, min_size=5, max_size=20)
    try:

        async def one(i: int) -> None:
            async with pool.acquire() as c:
                await audit.append(
                    c,
                    event_type="access.allowed",
                    decision="allow",
                    session_id=f"run-{i:03d}",
                    resource=f"opportunity:{i:03d}",
                )

        await asyncio.gather(*(one(i) for i in range(CONCURRENT_WRITES)))
    finally:
        await pool.close()

    rows = await audit.fetch_chain(conn)
    assert len(rows) == CONCURRENT_WRITES

    result = audit.verify_chain(rows)
    assert result.valid, str(result)
    assert result.entries_verified == CONCURRENT_WRITES

    # Name the specific failure the lock prevents: a fork shows up as two
    # entries claiming the same predecessor.
    prevs = [r["prev_hash"] for r in rows]
    assert len(set(prevs)) == len(prevs), "Two entries share a prev_hash - the chain forked"


async def test_the_lock_is_what_makes_that_pass(conn):
    """Diagnostic, not a guarantee.

    A concurrency test can pass for the wrong reason - if writes happen to
    serialise on their own, it proves nothing. This runs the same workload with
    the lock deliberately omitted and expects the chain to break. If it does
    not, the test above is inconclusive rather than wrong, so this reports
    inconclusive instead of failing the build.
    """

    async def append_without_lock(c) -> None:
        async with c.transaction():
            prev = (
                await c.fetchval("SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                or audit.GENESIS
            )
            await asyncio.sleep(0)  # yield, so interleaving is actually possible
            seq = await c.fetchval("SELECT nextval('audit_events_seq_seq')")
            row = {c_: None for c_ in audit.COLUMNS}
            row |= {
                "seq": seq,
                "ts": datetime.now(UTC),
                "event_type": "access.allowed",
                "decision": "allow",
                "prev_hash": prev,
            }
            row["entry_hash"] = audit.compute_entry_hash(prev, row)
            ph = ", ".join(f"${i}" for i in range(1, len(audit.COLUMNS) + 1))
            await c.execute(
                f"INSERT INTO audit_events ({', '.join(audit.COLUMNS)}) VALUES ({ph})",
                *(row[c_] for c_ in audit.COLUMNS),
            )

    async def one() -> None:
        async with pool.acquire() as c:
            await append_without_lock(c)

    pool = await asyncpg.create_pool(OWNER_DSN, min_size=5, max_size=20)
    try:
        await asyncio.gather(*(one() for _ in range(60)))
    finally:
        await pool.close()

    result = audit.verify_chain(await audit.fetch_chain(conn))
    if result.valid:
        pytest.skip(
            "Unlocked writes happened to serialise this run, so the concurrency "
            "test above is inconclusive rather than proven. Re-run."
        )
    assert not result.valid


# --- append-only, enforced by the database ---------------------------------


@pytest.fixture
async def app_conn(conn):
    """Connection as gatekeep_app - the role services actually use."""
    try:
        c = await asyncpg.connect(APP_DSN)
    except asyncpg.InvalidAuthorizationSpecificationError:
        pytest.skip("gatekeep_app role does not exist. Run `make migrate`.")
    try:
        yield c
    finally:
        await c.close()


async def test_app_role_can_append(app_conn):
    row = await audit.append(app_conn, event_type="grant.approved", decision="allow")
    assert row["entry_hash"]


async def test_app_role_cannot_rewrite_history(app_conn):
    """Section 5.1: enforce append-only at the database level, not in application
    code. Application-level enforcement is a code review away from gone."""
    await audit.append(
        app_conn, event_type="access.denied", decision="deny", reason="policy_denied"
    )

    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("UPDATE audit_events SET decision = 'allow'")

    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("DELETE FROM audit_events")
