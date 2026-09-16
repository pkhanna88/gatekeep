"""Connection pool and Redis client shared by a service's request handlers."""

from __future__ import annotations

import json

import asyncpg
import redis.asyncio as aioredis

from app import settings


async def _init_connection(conn: asyncpg.Connection) -> None:
    # JSONB columns come back as Python objects, not strings.
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def create_pool() -> asyncpg.Pool:
    return await asyncpg.create_pool(
        settings.APP_DSN, min_size=1, max_size=10, init=_init_connection
    )


def create_redis() -> aioredis.Redis:
    # Short timeouts: a hung Redis must fall through to Postgres quickly, not
    # stall the request path.
    return aioredis.from_url(
        settings.REDIS_URL, socket_timeout=0.5, socket_connect_timeout=0.5, decode_responses=True
    )
