"""Write an audit entry from a request handler.

Thin wrapper over audit.append (INF's chain code, unchanged) that borrows a
pooled connection. Every service writes through here; the advisory lock inside
append() is what keeps three writer processes on one unforked chain.
"""

from __future__ import annotations

from typing import Any

from app import audit


async def record(pool, **event: Any) -> dict[str, Any]:
    async with pool.acquire() as conn:
        return await audit.append(conn, **event)
