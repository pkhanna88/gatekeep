"""
The audit chain. Highest-care code in the repository.

Appendix A asks every new joiner to read this file and explain why the advisory
lock is there, so the short version first:

    Each entry stores the hash of the entry before it. Computing an entry means
    reading the current last hash, then inserting. If two requests do that at
    the same time, both read the SAME last hash, and both write entries claiming
    to follow it. The chain forks. Nothing errors. Nobody notices - until a
    verifier runs weeks later and reports the log as tampered, which is worse
    than useless because it is not true.

    pg_advisory_xact_lock on a fixed key makes read-prev-then-insert atomic
    across every connection and every control-plane instance. It is held for the
    life of the transaction and released on commit or rollback.

Section 3.6 offers two acceptable answers - a single writer queue, or the
advisory lock. We use the lock because it survives running more than one
control-plane instance, which a queue in one process does not.

What this buys us is tamper-EVIDENCE, not tamper-proofing (section 2.11). We
cannot stop a DBA editing a row. We can guarantee it is detectable, and that is
the property that lets a customer hand an export to a regulator.

--

Two things in here are deliberate and easy to "improve" by mistake:

1. compute_entry_hash serialises a FIXED field list with sort_keys=True and
   fixed separators. Section 5.4 calls this load-bearing, and it is: if
   serialisation is not byte-identical between writing and verifying, every
   entry reads as tampered. Do not add a field, reorder anything, or switch
   json library without re-hashing the whole chain.

2. `reason` is stored on the row but is NOT in the canonical field list, so it
   is not covered by the hash. That is section 5.4 as written, and we follow it
   so verification stays interoperable - but it does mean the stated reason for
   a denial can be altered without breaking the chain. Logged as a known gap in
   docs/SECURITY.md rather than silently fixed here, because changing the
   canonical form needs a second reviewer and a migration plan for existing
   entries.

Per section 9.2, any change to this file requires a second reviewer.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

GENESIS = "0" * 64

# The advisory lock key. Any constant works as long as every writer uses the
# same one; hashtext() turns the name into the bigint the lock function wants.
CHAIN_LOCK_KEY = "gatekeep_audit_chain"

# Section 5.4, verbatim and in this order. See note 1 above before touching it.
CANONICAL_FIELDS = (
    "seq",
    "ts",
    "event_type",
    "principal_sub",
    "agent_id",
    "session_id",
    "grant_id",
    "resource",
    "action",
    "decision",
    "payload_digest",
)

# Every column we write. `reason` is here but not in CANONICAL_FIELDS - note 2.
COLUMNS = (
    "seq",
    "ts",
    "event_type",
    "principal_sub",
    "agent_id",
    "session_id",
    "grant_id",
    "resource",
    "action",
    "decision",
    "reason",
    "payload_digest",
    "prev_hash",
    "entry_hash",
)


def compute_entry_hash(prev_hash: str, event: Mapping[str, Any]) -> str:
    """SHA-256 over the previous hash concatenated with this entry's canonical form.

    Section 5.4. `ts` is rendered with datetime.isoformat(); everything else is
    passed through json.dumps. Missing optional fields serialise as null, which
    is why the field list is fixed rather than derived from the event - an event
    that happens to omit `resource` must hash the same as one that sets it to
    None, or writer and verifier disagree.
    """
    canonical = json.dumps(
        {
            field: (
                event[field].isoformat()
                if field == "ts" and isinstance(event.get(field), datetime)
                else event.get(field)
            )
            for field in CANONICAL_FIELDS
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


async def append(conn, **event: Any) -> dict[str, Any]:
    """Append one entry, correctly chained. Returns the row as written.

    `conn` is an asyncpg connection. The caller owns the connection; we own the
    transaction, because the advisory lock has to span read-prev and insert and
    nothing else may sit between them.
    """
    unknown = set(event) - set(COLUMNS)
    if unknown:
        raise ValueError(
            f"Unknown audit field(s): {sorted(unknown)}. "
            f"Adding a field means deciding whether it belongs in CANONICAL_FIELDS, "
            f"which changes every hash. See the module docstring."
        )

    async with conn.transaction():
        # Serialise chain writes. Everything below this line is atomic with
        # respect to any other writer taking the same lock.
        await conn.execute("SELECT pg_advisory_xact_lock(hashtext($1))", CHAIN_LOCK_KEY)

        prev = await conn.fetchval("SELECT entry_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
        prev = prev or GENESIS

        # seq and ts are generated here rather than left to the column defaults,
        # because both are inside the hash and we must write exactly what we hashed.
        seq = await conn.fetchval("SELECT nextval('audit_events_seq_seq')")
        ts = datetime.now(UTC)

        row: dict[str, Any] = {c: event.get(c) for c in COLUMNS}
        row["seq"] = seq
        row["ts"] = ts
        row["prev_hash"] = prev
        row["entry_hash"] = compute_entry_hash(prev, row)

        placeholders = ", ".join(f"${i}" for i in range(1, len(COLUMNS) + 1))
        await conn.execute(
            f"INSERT INTO audit_events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
            *(row[c] for c in COLUMNS),
        )
        return row


@dataclass(frozen=True)
class VerificationResult:
    """What a verifier hands an auditor. `valid=False` names the exact entry."""

    valid: bool
    entries_verified: int = 0
    broken_at_seq: int | None = None
    broken_at_ts: datetime | None = None
    message: str = ""

    def __str__(self) -> str:
        if self.valid:
            return f"Chain intact. {self.entries_verified} entries verified."
        return self.message


def verify_chain(rows: Sequence[Mapping[str, Any]]) -> VerificationResult:
    """Walk the chain and report the first break. Section 7.4.

    `rows` must be ordered by seq ascending and contain CANONICAL_FIELDS plus
    prev_hash and entry_hash. Use fetch_chain().
    """
    prev = GENESIS
    for i, row in enumerate(rows):
        expected = compute_entry_hash(prev, row)
        if expected != row["entry_hash"]:
            # Distinguish the two ways a chain breaks, because they mean
            # different things to whoever is reading the report.
            if row["prev_hash"] != prev:
                detail = (
                    f"entry {row['seq']} claims to follow {row['prev_hash'][:16]}... "
                    f"but the previous entry hashes to {prev[:16]}..., so an entry "
                    f"was removed or reordered"
                )
            else:
                detail = (
                    f"entry {row['seq']} is chained correctly but its contents no "
                    f"longer hash to its stored entry_hash, so the row was edited"
                )
            return VerificationResult(
                valid=False,
                entries_verified=i,
                broken_at_seq=row["seq"],
                broken_at_ts=row.get("ts"),
                message=f"Chain integrity failure at entry {row['seq']}: {detail}",
            )
        prev = row["entry_hash"]
    return VerificationResult(valid=True, entries_verified=len(rows))


async def fetch_chain(conn, *, session_id: str | None = None) -> list[dict[str, Any]]:
    """Read the chain in seq order, as plain dicts ready for verify_chain.

    Note there is no session filter applied to verification: a chain is only
    verifiable end to end. `session_id` filters what is RETURNED for display,
    never what is verified.
    """
    rows = await conn.fetch(f"SELECT {', '.join(COLUMNS)} FROM audit_events ORDER BY seq")
    out = [dict(r) for r in rows]
    if session_id is not None:
        out = [r for r in out if r["session_id"] == session_id]
    return out
