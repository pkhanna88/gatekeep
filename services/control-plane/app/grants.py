"""
Grant lifecycle and Invariant 1. Section 4.3 / 7.1.

    pending --approve--> active --revoke/killswitch--> revoked
       |                   |
       +--reject----> rejected       +--time--> expired
       +--over-scoped approval--> rejected

The security heart of the control plane is `approve_grant`:

  1. The approver must BE the principal named on the grant. Not an admin, not
     a delegate. An admin approving on Priya's behalf silently destroys the
     accountability chain we sell. The grant stays pending so Priya still can.
  2. INVARIANT 1: every requested scope is checked against OpenFGA as the
     principal. All failures are collected so the human sees everything wrong
     at once. Any failure rejects the grant permanently - as requested it can
     never become valid, so leaving it pending would only invite retries.
  3. If OpenFGA cannot answer, the approval is refused (503) and the grant stays
     pending. We never approve on an unverifiable check.

Every refusal writes an audit entry with a reason. A denial that leaves no trace
is a hole in the evidence (section 7.1).

Per section 9.2, changes to this file need a second reviewer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from app import events, ids, settings
from app.agents import current_agent
from app.errors import ApiError
from app.fga import PolicyUnavailable
from app.humans import ROLE_ADMIN, Human, current_human
from app.revocation import mark_revoked
from app.scopes import ScopeError, parse_scope, parse_scopes

router = APIRouter(prefix="/v1/grants", tags=["grants"])

STATUSES = ("pending", "active", "rejected", "revoked", "expired")
_VERB = {"read": "Read", "write": "Write to"}


def describe_scope(raw: str) -> str:
    """Plain English for the approver (section 3.9: Priya is not an engineer)."""
    s = parse_scope(raw)
    return f"{_VERB[s.action]} {s.rtype} {s.rid} in {s.system.capitalize()}"


def to_json(row) -> dict:
    expires_at = row["expires_at"]
    remaining = int((expires_at - datetime.now(UTC)).total_seconds())
    return {
        "id": row["id"],
        "status": row["status"],
        "principal_sub": row["principal_sub"],
        "agent_id": row["agent_id"],
        "purpose": row["purpose"],
        "scopes": row["scopes"],
        "scope_descriptions": [describe_scope(s) for s in row["scopes"]],
        "constraints": row["constraints"],
        "expires_at": expires_at.isoformat(),
        "expires_in_minutes": max(0, remaining // 60),
        "approved_at": row["approved_at"].isoformat() if row["approved_at"] else None,
        "approved_by": row["approved_by"],
        "revoked_at": row["revoked_at"].isoformat() if row["revoked_at"] else None,
        "revoked_by": row["revoked_by"],
        "revoke_reason": row["revoke_reason"],
        "created_at": row["created_at"].isoformat(),
    }


async def expire_due(pool) -> None:
    """Move grants past expires_at to `expired`, one audit entry each.

    Called before any read or transition, so status is never stale when a
    decision depends on it. The token service and PEP do not rely on this -
    they compare expires_at themselves.
    """
    rows = await pool.fetch(
        "UPDATE grants SET status = 'expired' "
        "WHERE status IN ('pending', 'active') AND expires_at <= now() "
        "RETURNING id, principal_sub, agent_id"
    )
    for r in rows:
        await events.record(
            pool,
            event_type="grant.expired",
            grant_id=r["id"],
            principal_sub=r["principal_sub"],
            agent_id=r["agent_id"],
            decision="deny",
            reason="expired",
        )


async def _load_visible(pool, grant_id: str, human: Human):
    row = await pool.fetchrow("SELECT * FROM grants WHERE id = $1", grant_id)
    # Someone else's grant reads as not found, not forbidden: its existence is not their business.
    if row is None or not (human.sees_everything or row["principal_sub"] == human.principal):
        raise ApiError(404, "grant_not_found", f"No grant {grant_id}")
    return row


# --- the agent asks -----------------------------------------------------------


class GrantRequest(BaseModel):
    agent_id: str
    principal_sub: str = Field(min_length=3, max_length=320)
    purpose: str = Field(min_length=3, max_length=500)
    scopes: list[str] = Field(min_length=1, max_length=50)
    constraints: dict = Field(default_factory=dict)
    ttl_minutes: int = Field(default=30, ge=1, le=480)


@router.post("", status_code=201)
async def request_grant(body: GrantRequest, request: Request, agent=Depends(current_agent)):
    """An agent asks a named human for a scoped, expiring slice of their authority."""
    pool = request.app.state.pool
    if body.agent_id != agent["id"]:
        raise ApiError(403, "agent_mismatch", "An agent may only request grants for itself")
    try:
        scopes = [str(s) for s in parse_scopes(body.scopes)]
    except ScopeError as e:
        raise ApiError(400, "invalid_scope", str(e)) from e

    grant_id = ids.grant_id()
    expires_at = datetime.now(UTC) + timedelta(minutes=body.ttl_minutes)
    row = await pool.fetchrow(
        "INSERT INTO grants "
        "(id, principal_sub, agent_id, purpose, scopes, constraints, status, expires_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7) RETURNING *",
        grant_id,
        body.principal_sub,
        agent["id"],
        body.purpose,
        scopes,
        body.constraints,
        expires_at,
    )
    await events.record(
        pool,
        event_type="grant.requested",
        grant_id=grant_id,
        principal_sub=body.principal_sub,
        agent_id=agent["id"],
        decision="allow",
    )
    return {**to_json(row), "approval_url": f"{settings.CONTROL_PLANE_URL}/v1/grants/{grant_id}"}


# --- the human looks ------------------------------------------------------------


@router.get("")
async def list_grants(
    request: Request,
    status: str | None = Query(None, description="pending | active | rejected | revoked | expired"),
    human: Human = Depends(current_human),
):
    """The approval queue. Analysts see grants naming them; admins and auditors see all."""
    pool = request.app.state.pool
    if status is not None and status not in STATUSES:
        raise ApiError(400, "invalid_status", f"status must be one of {', '.join(STATUSES)}")
    await expire_due(pool)
    rows = await pool.fetch(
        "SELECT * FROM grants WHERE ($1::text IS NULL OR status = $1) "
        "AND ($2::bool OR principal_sub = $3) ORDER BY created_at DESC LIMIT 200",
        status,
        human.sees_everything,
        human.principal,
    )
    return {"grants": [to_json(r) for r in rows]}


@router.get("/{grant_id}")
async def get_grant(grant_id: str, request: Request, human: Human = Depends(current_human)):
    pool = request.app.state.pool
    await expire_due(pool)
    return to_json(await _load_visible(pool, grant_id, human))


# --- the human decides ----------------------------------------------------------


@router.post("/{grant_id}/approve")
async def approve_grant(grant_id: str, request: Request, human: Human = Depends(current_human)):
    pool, fga = request.app.state.pool, request.app.state.fga
    await expire_due(pool)
    grant = await pool.fetchrow("SELECT * FROM grants WHERE id = $1", grant_id)
    if grant is None:
        raise ApiError(404, "grant_not_found", f"No grant {grant_id}")

    base = {
        "grant_id": grant_id,
        "principal_sub": grant["principal_sub"],
        "agent_id": grant["agent_id"],
    }

    # 1. The approver must be the principal. Checked before anything else.
    if human.principal != grant["principal_sub"]:
        await events.record(
            pool,
            event_type="grant.rejected",
            decision="deny",
            reason=f"approver_is_not_principal:{human.principal}",
            **base,
        )
        raise ApiError(
            403,
            "approver_is_not_principal",
            f"Only {grant['principal_sub']} may approve this grant. "
            f"You are {human.principal}. Nobody can approve on someone else's behalf.",
        )

    if grant["status"] != "pending":
        raise ApiError(409, "grant_not_pending", f"Grant is {grant['status']}, not pending")

    # 2. INVARIANT 1 - the principal cannot delegate what they do not hold.
    missing = []
    try:
        for scope in parse_scopes(grant["scopes"]):
            allowed = await fga.check(
                f"user:{grant['principal_sub']}", scope.relation, scope.fga_object
            )
            if not allowed:
                missing.append(str(scope))
    except (PolicyUnavailable, ScopeError) as e:
        # 3. Cannot prove the subset, so cannot approve. Grant stays pending.
        await events.record(
            pool, event_type="grant.rejected", decision="deny", reason="policy_unavailable", **base
        )
        raise ApiError(
            503, "policy_unavailable", f"Could not verify scopes, approval refused: {e}"
        ) from e

    if missing:
        await pool.execute(
            "UPDATE grants SET status = 'rejected', revoke_reason = 'scope_exceeds_principal' "
            "WHERE id = $1 AND status = 'pending'",
            grant_id,
        )
        await events.record(
            pool,
            event_type="grant.rejected",
            decision="deny",
            reason="scope_exceeds_principal",
            **base,
        )
        raise ApiError(
            403,
            "scope_exceeds_principal",
            f"Principal does not hold: {', '.join(missing)}",
            offending_scopes=missing,
        )

    # Conditional update: a concurrent approve/revoke cannot be overwritten.
    row = await pool.fetchrow(
        "UPDATE grants SET status = 'active', approved_at = now(), approved_by = $2 "
        "WHERE id = $1 AND status = 'pending' AND expires_at > now() RETURNING *",
        grant_id,
        human.principal,
    )
    if row is None:
        raise ApiError(409, "grant_not_pending", "Grant changed state during approval")
    await events.record(pool, event_type="grant.approved", decision="allow", **base)
    return to_json(row)


@router.post("/{grant_id}/reject")
async def reject_grant(grant_id: str, request: Request, human: Human = Depends(current_human)):
    pool = request.app.state.pool
    await expire_due(pool)
    grant = await _load_visible(pool, grant_id, human)
    if human.principal != grant["principal_sub"]:
        raise ApiError(
            403,
            "approver_is_not_principal",
            f"Only {grant['principal_sub']} may decline this grant",
        )
    row = await pool.fetchrow(
        "UPDATE grants SET status = 'rejected', revoke_reason = 'declined_by_principal' "
        "WHERE id = $1 AND status = 'pending' RETURNING *",
        grant_id,
    )
    if row is None:
        raise ApiError(409, "grant_not_pending", f"Grant is {grant['status']}, not pending")
    await events.record(
        pool,
        event_type="grant.rejected",
        grant_id=grant_id,
        principal_sub=grant["principal_sub"],
        agent_id=grant["agent_id"],
        decision="deny",
        reason="declined_by_principal",
    )
    return to_json(row)


class RevokeBody(BaseModel):
    reason: str = Field(default="revoked_by_user", min_length=1, max_length=200)


@router.post("/{grant_id}/revoke")
async def revoke_grant(
    grant_id: str,
    request: Request,
    body: RevokeBody | None = None,
    human: Human = Depends(current_human),
):
    """Revoke one grant. The principal or a security admin. Effective on the next request."""
    pool, redis = request.app.state.pool, request.app.state.redis
    reason = (body or RevokeBody()).reason
    grant = await _load_visible(pool, grant_id, human)
    if human.principal != grant["principal_sub"] and ROLE_ADMIN not in human.roles:
        raise ApiError(403, "forbidden", "Only the principal or a security admin may revoke")

    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            "UPDATE grants SET status = 'revoked', revoked_at = now(), "
            "revoked_by = $2, revoke_reason = $3 "
            "WHERE id = $1 AND status IN ('pending', 'active') RETURNING *",
            grant_id,
            human.principal,
            reason,
        )
        if row is None:
            raise ApiError(409, "grant_not_revocable", f"Grant is {grant['status']}")
        await conn.execute(
            "UPDATE agent_sessions SET status = 'killed', ended_at = now() "
            "WHERE grant_id = $1 AND status = 'running'",
            grant_id,
        )
    # Postgres is committed - the revocation is already true. Now the fast path.
    await mark_revoked(redis, [grant_id])
    await events.record(
        pool,
        event_type="grant.revoked",
        grant_id=grant_id,
        principal_sub=grant["principal_sub"],
        agent_id=grant["agent_id"],
        decision="deny",
        reason=f"{reason} by {human.principal}",
    )
    return to_json(row)
