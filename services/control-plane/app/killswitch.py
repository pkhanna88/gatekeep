"""
The kill switch. Section 1.6: one control, whole estate, effective within seconds.

    POST /v1/killswitch        security-admin only

In ONE Postgres transaction: every pending or active grant becomes revoked and
every running session becomes killed. Postgres commits first, so the kill is
true before anything else happens; then Redis is told (fast path for the PEP);
then the evidence is written - one `killswitch.activated` plus one
`grant.revoked` per grant, so each agent's trail shows why it stopped.

Agents holding still-valid five-minute tokens are stopped by the PEP, which
checks revocation on every request. The token TTL is only defence in depth.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from app import events
from app.humans import ROLE_ADMIN, Human, current_human, require_role
from app.revocation import mark_revoked

router = APIRouter(tags=["killswitch"])


class KillBody(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


@router.get("/v1/killswitch/preview")
async def preview(request: Request, human: Human = Depends(current_human)):
    """What pressing the button would stop - section 3.9's confirmation modal, as data."""
    require_role(human, ROLE_ADMIN)
    pool = request.app.state.pool
    grants = await pool.fetchval(
        "SELECT count(*) FROM grants WHERE status IN ('pending', 'active')"
    )
    sessions = await pool.fetchval("SELECT count(*) FROM agent_sessions WHERE status = 'running'")
    return {"grants_to_revoke": grants, "sessions_to_kill": sessions}


@router.post("/v1/killswitch")
async def activate(body: KillBody, request: Request, human: Human = Depends(current_human)):
    require_role(human, ROLE_ADMIN)
    pool, redis = request.app.state.pool, request.app.state.redis

    async with pool.acquire() as conn, conn.transaction():
        grants = await conn.fetch(
            "UPDATE grants SET status = 'revoked', revoked_at = now(), revoked_by = $1, "
            "revoke_reason = $2 WHERE status IN ('pending', 'active') "
            "RETURNING id, principal_sub, agent_id",
            human.principal,
            f"killswitch: {body.reason}",
        )
        sessions = await conn.fetch(
            "UPDATE agent_sessions SET status = 'killed', ended_at = now() "
            "WHERE status = 'running' RETURNING id"
        )
    activated_at = datetime.now(UTC)

    await mark_revoked(redis, [g["id"] for g in grants])

    await events.record(
        pool,
        event_type="killswitch.activated",
        principal_sub=human.principal,
        decision="deny",
        reason=f"{len(grants)} grants revoked, {len(sessions)} sessions killed: {body.reason}",
    )
    for g in grants:
        await events.record(
            pool,
            event_type="grant.revoked",
            grant_id=g["id"],
            principal_sub=g["principal_sub"],
            agent_id=g["agent_id"],
            decision="deny",
            reason=f"killswitch by {human.principal}",
        )

    return {
        "activated_at": activated_at.isoformat(),
        "activated_by": human.principal,
        "grants_revoked": len(grants),
        "sessions_killed": len(sessions),
        "grant_ids": [g["id"] for g in grants],
    }
