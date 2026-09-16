"""
Control plane - port 8000. Section 4.3.

The only writer to grants. Owns the agent registry, grant lifecycle, revocation
state and the kill switch, and serves the audit trail.

    make services        runs this alongside the token service, PEP and mock Salesforce
    http://localhost:8000/docs
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import agents, audit_api, db, errors, grants, killswitch, settings
from app.fga import FGA
from app.jwtverify import JWKSCache


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await db.create_pool()
    app.state.redis = db.create_redis()
    app.state.fga = FGA()
    app.state.keycloak_jwks = JWKSCache(settings.KEYCLOAK_JWKS)
    try:
        yield
    finally:
        await app.state.fga.aclose()
        await app.state.redis.aclose()
        await app.state.pool.close()


app = FastAPI(
    title="Gatekeep control plane",
    description="Agents, grants, approvals (Invariant 1), revocation, kill switch, audit.",
    version="0.1.0",
    lifespan=lifespan,
)
errors.install(app)
app.include_router(agents.router)
app.include_router(grants.router)
app.include_router(killswitch.router)
app.include_router(audit_api.router)


@app.get("/healthz", tags=["health"])
async def healthz():
    await app.state.pool.fetchval("SELECT 1")
    return {"status": "ok", "service": "control-plane"}
