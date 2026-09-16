"""
Agent registry and bootstrap credentials. Section 3.11 / Day 6.

An agent registers once and receives a bootstrap credential, shown exactly once:

    gkb.<key_id>.<secret>

Only an argon2id hash of the full credential is stored. `key_id` is a public
lookup handle (argon2 hashes are salted, so they cannot be searched by value);
`secret` is 32 random bytes. The credential proves which agent is calling when
it requests a grant (here) and when it exchanges one for a token (token service).

This is the weak link section 3.11 names openly: a bootstrap credential, not
cryptographic workload attestation. SPIFFE is Phase 2.
"""

from __future__ import annotations

import asyncio
import re
import secrets

import asyncpg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, Field

from app import events
from app.errors import ApiError
from app.humans import ROLE_ADMIN, Human, current_human, require_role

router = APIRouter(prefix="/v1/agents", tags=["agents"])

_hasher = PasswordHasher()  # argon2id with the library's current recommended parameters
_AGENT_ID = re.compile(r"^agent://[a-z0-9-]+/[a-z0-9-]+$")
_CREDENTIAL = re.compile(r"^gkb\.([A-Za-z0-9_-]{8,32})\.([A-Za-z0-9_-]{20,64})$")

# Verifying against a hash nobody holds keeps timing the same for an unknown
# key id and a wrong secret, so the response time does not reveal which it was.
_DUMMY_HASH = _hasher.hash("gatekeep-dummy")


def new_credential() -> tuple[str, str]:
    key_id = secrets.token_urlsafe(9)
    return key_id, f"gkb.{key_id}.{secrets.token_urlsafe(32)}"


async def authenticate_agent(pool, credential: str | None) -> asyncpg.Record | None:
    """Return the active agent this credential belongs to, or None. Never raises on bad input."""
    m = _CREDENTIAL.match(credential or "")
    row = None
    if m:
        row = await pool.fetchrow("SELECT * FROM agents WHERE bootstrap_key_id = $1", m.group(1))
    stored = row["bootstrap_hash"] if row else _DUMMY_HASH
    try:
        await asyncio.to_thread(_hasher.verify, stored, credential or "")
    except (VerificationError, InvalidHashError):
        return None
    if row is None or row["status"] != "active":
        return None
    return row


class AgentIn(BaseModel):
    id: str = Field(
        description="agent://<org>/<name>, lowercase", examples=["agent://acme/invoice-reconciler"]
    )
    display_name: str = Field(min_length=1, max_length=200)
    owner_email: str = Field(min_length=3, max_length=320)


def _public(row) -> dict:
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "owner_email": row["owner_email"],
        "status": row["status"],
        "created_at": row["created_at"].isoformat(),
    }


@router.post("", status_code=201)
async def register_agent(body: AgentIn, request: Request, human: Human = Depends(current_human)):
    """Register an agent. Security admins only. The credential is in this response, nowhere else."""
    require_role(human, ROLE_ADMIN)
    if not _AGENT_ID.match(body.id):
        raise ApiError(
            400, "invalid_agent_id", "Agent id must look like agent://acme/invoice-reconciler"
        )

    pool = request.app.state.pool
    key_id, credential = new_credential()
    digest = await asyncio.to_thread(_hasher.hash, credential)
    try:
        row = await pool.fetchrow(
            "INSERT INTO agents (id, display_name, owner_email, bootstrap_key_id, bootstrap_hash) "
            "VALUES ($1, $2, $3, $4, $5) RETURNING *",
            body.id,
            body.display_name,
            body.owner_email,
            key_id,
            digest,
        )
    except asyncpg.UniqueViolationError as e:
        raise ApiError(409, "agent_exists", f"{body.id} is already registered") from e

    await events.record(
        pool,
        event_type="agent.registered",
        principal_sub=human.principal,
        agent_id=body.id,
        decision="allow",
    )
    return {
        **_public(row),
        "bootstrap_credential": credential,
        "warning": "Shown once. Gatekeep stores only an argon2id hash and cannot show it again.",
    }


@router.get("")
async def list_agents(request: Request, human: Human = Depends(current_human)):
    rows = await request.app.state.pool.fetch("SELECT * FROM agents ORDER BY created_at")
    return {"agents": [_public(r) for r in rows]}


async def current_agent(request: Request, authorization: str | None = Header(None)):
    """Dependency: the calling agent, from `Authorization: Bearer gkb....`."""
    credential = (
        authorization[7:].strip()
        if authorization and authorization.lower().startswith("bearer ")
        else None
    )
    agent = await authenticate_agent(request.app.state.pool, credential)
    if agent is None:
        raise ApiError(401, "unauthenticated", "Agent bootstrap credential rejected")
    return agent
