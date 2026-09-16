"""
tools/audit-verify - walk the audit chain from genesis and name the first break.

    make audit-verify

Section 7.4: "the strongest single moment in the sales demo". Runs directly
against Postgres with INF's verify_chain, so it needs none of the Gatekeep
services running - an auditor can run it against a restored backup.

Connects as gatekeep_app: reading the chain needs SELECT, nothing more.
Exit code 0 = intact, 1 = broken, 2 = could not reach the database.
"""

import argparse
import asyncio
import os
import pathlib
import sys

import asyncpg

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "services" / "control-plane")
)
from app import audit, settings  # noqa: E402

NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


def c(code: str, s: str) -> str:
    return s if NO_COLOR else f"\033[{code}m{s}\033[0m"


async def main(dsn: str) -> int:
    conn = await asyncpg.connect(dsn)
    try:
        rows = await audit.fetch_chain(conn)
    finally:
        await conn.close()

    result = audit.verify_chain(rows)
    print(f"\n  Walked {len(rows)} audit entries from genesis.\n")
    if result.valid:
        print(f"  {c('32', 'CHAIN INTACT')}   {result.entries_verified} entries verified.")
        if rows:
            print(f"  Head of chain  seq {rows[-1]['seq']}  {rows[-1]['entry_hash']}")
        print()
        return 0

    print(f"  {c('31', 'CHAIN BROKEN')}   at entry {result.broken_at_seq}  ({result.broken_at_ts})")
    print(f"  {result.message}")
    print(
        f"  Entries 1..{result.entries_verified} verify. "
        f"Everything from {result.broken_at_seq} on is unproven.\n"
    )
    return 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--dsn", default=settings.APP_DSN)
    args = ap.parse_args()
    try:
        sys.exit(asyncio.run(main(args.dsn)))
    except (OSError, asyncpg.PostgresError) as e:
        print(
            f"\n  Cannot read the audit chain: {e}\n"
            "  Is the stack up and migrated?  make dev && make migrate\n"
        )
        sys.exit(2)
