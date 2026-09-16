"""
Token service - port 8001. Section 4.3.

Swaps an approved grant plus an agent's bootstrap credential for a five-minute
token (RFC 8693), signed by OpenBao transit. Publishes the public keys at
/.well-known/jwks.json so the PEP can verify tokens without calling us.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from app import db, errors
from fastapi import FastAPI

from token_service import exchange
from token_service.signing import SigningUnavailable, TransitSigner


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await db.create_pool()
    app.state.redis = db.create_redis()
    app.state.signer = TransitSigner()
    try:
        yield
    finally:
        await app.state.signer.aclose()
        await app.state.redis.aclose()
        await app.state.pool.close()


app = FastAPI(
    title="Gatekeep token service",
    description="RFC 8693 token exchange (Invariant 2) and JWKS.",
    version="0.1.0",
    lifespan=lifespan,
)
errors.install(app)
app.include_router(exchange.router)


@app.get("/.well-known/jwks.json", tags=["token exchange"])
async def jwks():
    try:
        return await app.state.signer.jwks()
    except SigningUnavailable as e:
        raise errors.ApiError(503, "signing_unavailable", str(e)) from e


@app.get("/healthz", tags=["health"])
async def healthz():
    await app.state.pool.fetchval("SELECT 1")
    return {"status": "ok", "service": "token-service"}
