"""
PEP proxy - port 8002. Section 4.3, the enforcement point.

    /proxy/<system>/<path>
    e.g. /proxy/salesforce/services/data/v60.0/sobjects/Opportunity/0065g00001NWD

Architectural rule, section 4.3: agents must have no network path to target
systems except through here. In this dev environment the mock Salesforce
enforces a weaker version of that - it refuses anything without the connector
credential only the PEP holds. Real egress control is a deployment requirement;
see docs/SECURITY.md section 9.1.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from app import db, settings
from app.fga import FGA
from app.jwtverify import JWKSCache
from fastapi import FastAPI, Request

from pep_proxy import pipeline
from pep_proxy.connectors.mock import MockSalesforceConnector


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await db.create_pool()
    app.state.redis = db.create_redis()
    app.state.fga = FGA()
    app.state.agent_jwks = JWKSCache(f"{settings.TOKEN_SERVICE_URL}/.well-known/jwks.json")
    app.state.connectors = {"salesforce": MockSalesforceConnector()}
    try:
        yield
    finally:
        for c in app.state.connectors.values():
            await c.aclose()
        await app.state.fga.aclose()
        await app.state.redis.aclose()
        await app.state.pool.close()


app = FastAPI(
    title="Gatekeep PEP proxy",
    description="Verifies, checks revocation, scope and policy, audits, then forwards.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.api_route("/proxy/{system}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(system: str, path: str, request: Request):
    return await pipeline.handle(system, path, request)


@app.get("/healthz")
async def healthz():
    await app.state.pool.fetchval("SELECT 1")
    return {"status": "ok", "service": "pep-proxy"}
