"""
Revocation: Redis for speed, Postgres for truth. Section 3.7.

The rule that matters: an empty Redis must never mean "nothing is revoked".
Redis is flushed on restart, can be evicted, can be down. So:

    is_grant_usable()
        1. Redis says revoked            -> not usable. Fast path, no DB hit.
        2. otherwise ask Postgres        -> the grant row is the authority:
                                            status must be 'active' and
                                            expires_at in the future.
        3. Redis down                    -> skip to 2.
        4. Redis down AND Postgres down  -> raise. Callers deny.

A Redis miss is never trusted as an allow, which is what makes
`test_revocation_survives_redis_flush` pass by construction rather than by
cache warming. The cost is one primary-key lookup per request, which is well
inside the latency budget. Recorded in docs/DECISIONS.md.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, datetime

import redis.asyncio as aioredis
from redis.exceptions import RedisError

log = logging.getLogger("gatekeep.revocation")

REVOKED_SET = "gk:revoked_grants"


async def mark_revoked(redis: aioredis.Redis, grant_ids: Iterable[str]) -> None:
    """Push revocations to the fast path. Postgres must already be committed.

    A Redis failure here is logged, not raised: the revocation is already true
    in Postgres, and step 2 above enforces it on the very next request.
    """
    ids = list(grant_ids)
    if not ids:
        return
    try:
        await redis.sadd(REVOKED_SET, *ids)
    except RedisError:
        log.warning(
            "redis unavailable while marking %d grant(s) revoked; postgres enforces", len(ids)
        )


async def grant_state(pool, redis: aioredis.Redis | None, grant_id: str) -> tuple[bool, str]:
    """Return (usable, reason). Raises if neither store can answer."""
    if redis is not None:
        try:
            if await redis.sismember(REVOKED_SET, grant_id):
                return False, "grant_revoked"
        except RedisError:
            log.warning("redis unavailable for revocation check; falling back to postgres")

    row = await pool.fetchrow("SELECT status, expires_at FROM grants WHERE id = $1", grant_id)
    if row is None:
        return False, "grant_not_found"
    if row["status"] == "revoked":
        return False, "grant_revoked"
    if row["status"] != "active":
        return False, f"grant_{row['status']}"
    if row["expires_at"] <= datetime.now(UTC):
        return False, "grant_expired"
    return True, "ok"
