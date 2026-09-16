"""Read side of the evidence: sessions, audit search, chain verification. Section 6.1."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app import audit
from app.errors import ApiError
from app.humans import ROLE_ADMIN, ROLE_AUDITOR, Human, current_human, require_role

router = APIRouter(tags=["audit"])


def _row(r) -> dict:
    d = dict(r)
    d["ts"] = d["ts"].isoformat()
    return d


@router.get("/v1/sessions")
async def list_sessions(
    request: Request, status: str | None = Query(None), human: Human = Depends(current_human)
):
    rows = await request.app.state.pool.fetch(
        "SELECT s.*, g.principal_sub, g.purpose FROM agent_sessions s "
        "JOIN grants g ON g.id = s.grant_id "
        "WHERE ($1::text IS NULL OR s.status = $1) AND ($2::bool OR g.principal_sub = $3) "
        "ORDER BY s.started_at DESC LIMIT 200",
        status,
        human.sees_everything,
        human.principal,
    )
    return {
        "sessions": [
            {
                **dict(r),
                "started_at": r["started_at"].isoformat(),
                "ended_at": r["ended_at"].isoformat() if r["ended_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/v1/audit")
async def search_audit(
    request: Request,
    agent_id: str | None = None,
    grant_id: str | None = None,
    session_id: str | None = None,
    event_type: str | None = None,
    decision: str | None = Query(None, description="allow | deny"),
    limit: int = Query(100, ge=1, le=1000),
    human: Human = Depends(current_human),
):
    """Newest first. Security admins and auditors only."""
    require_role(human, ROLE_ADMIN, ROLE_AUDITOR)
    if decision is not None and decision not in ("allow", "deny"):
        raise ApiError(400, "invalid_decision", "decision must be allow or deny")
    rows = await request.app.state.pool.fetch(
        f"SELECT {', '.join(audit.COLUMNS)} FROM audit_events WHERE "
        "($1::text IS NULL OR agent_id = $1) AND ($2::text IS NULL OR grant_id = $2) AND "
        "($3::text IS NULL OR session_id = $3) AND ($4::text IS NULL OR event_type = $4) AND "
        "($5::text IS NULL OR decision = $5) ORDER BY seq DESC LIMIT $6",
        agent_id,
        grant_id,
        session_id,
        event_type,
        decision,
        limit,
    )
    return {"events": [_row(r) for r in rows]}


@router.get("/v1/audit/verify")
async def verify(request: Request, human: Human = Depends(current_human)):
    """Walk the whole chain from genesis and name the first broken entry, if any."""
    require_role(human, ROLE_ADMIN, ROLE_AUDITOR)
    async with request.app.state.pool.acquire() as conn:
        result = audit.verify_chain(await audit.fetch_chain(conn))
    return {
        "valid": result.valid,
        "entries_verified": result.entries_verified,
        "broken_at_seq": result.broken_at_seq,
        "broken_at_ts": result.broken_at_ts.isoformat() if result.broken_at_ts else None,
        "message": str(result),
    }
