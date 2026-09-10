"""
Apply the .sql files in this directory, in filename order.

[INF stand-in for `make migrate`.] BE1 replaces this with alembic on Day 1.
Deliberately about thirty lines: it exists so Day 4's audit chain has a table to
write to, not to become a migration framework anyone has to maintain.

    make migrate
"""

import asyncio
import pathlib
import sys

import asyncpg

# Migrations connect as the owner. Services connect as gatekeep_app, which
# cannot UPDATE or DELETE audit rows - see 0001_audit_events.sql.
DSN = "postgres://gatekeep:gatekeep@localhost:5432/gatekeep"

HERE = pathlib.Path(__file__).resolve().parent


async def main() -> int:
    files = sorted(HERE.glob("*.sql"))
    if not files:
        print("No .sql files found.")
        return 0

    conn = await asyncpg.connect(DSN)
    try:
        for f in files:
            await conn.execute(f.read_text())
            print(f"applied     {f.name}")
        tables = await conn.fetchval(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema='public' AND table_name='audit_events'"
        )
        print(f"audit_events present: {bool(tables)}")
    finally:
        await conn.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except OSError as e:
        print(f"\n  Cannot reach Postgres: {e}\n\n  Is the stack up?  make dev\n")
        sys.exit(2)
