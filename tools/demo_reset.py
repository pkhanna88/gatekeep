"""
make demo-reset - back to a clean demo state in one command. Section 3.10.

  1. Empties agents, grants, sessions and the audit chain (as the table owner -
     the application role cannot, by design)
  2. Clears the Redis revoked set
  3. Re-runs `make seed`: policy model, tuples, acceptance checks, signing key
  4. Resets the mock Salesforce's records and request log, if it is running

Local database only. It refuses anything that is not localhost.
"""

import asyncio
import pathlib
import subprocess
import sys

import asyncpg
import httpx
import redis

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "services" / "control-plane"))
from app import settings  # noqa: E402
from app.revocation import REVOKED_SET  # noqa: E402

OWNER_DSN = "postgres://gatekeep:gatekeep@localhost:5432/gatekeep"


async def reset_db() -> None:
    assert "localhost" in OWNER_DSN
    conn = await asyncpg.connect(OWNER_DSN)
    try:
        await conn.execute(
            "TRUNCATE audit_events, agent_sessions, grants, agents RESTART IDENTITY CASCADE"
        )
    finally:
        await conn.close()
    print("database    agents, grants, sessions, audit chain emptied")


def main() -> int:
    subprocess.run(
        [sys.executable, str(REPO / "services/control-plane/migrations/apply.py")], check=True
    )
    asyncio.run(reset_db())

    redis.from_url(settings.REDIS_URL).delete(REVOKED_SET)
    print("redis       revoked set cleared")

    print()
    if subprocess.run([sys.executable, str(REPO / "deploy/seed/seed.py")]).returncode != 0:
        return 1

    try:
        r = httpx.post(
            f"{settings.MOCK_SALESFORCE_URL}/_gatekeep/reset",
            headers={"Authorization": f"Bearer {settings.MOCK_SALESFORCE_SECRET}"},
            timeout=5,
        )
        r.raise_for_status()
        print("\nsalesforce  mock records and request log reset")
    except httpx.HTTPError:
        print("\nsalesforce  mock not running - it starts clean with `make services`")

    print("\nClean demo state. Run:  make demo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
