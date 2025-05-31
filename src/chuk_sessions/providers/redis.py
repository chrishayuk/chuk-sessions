# ===========================================================================
# chuk_sessions/providers/redis.py
# ===========================================================================
"""Redis-backed session store (wraps redis.asyncio)."""
from __future__ import annotations

import os, ssl, redis.asyncio as aioredis
from contextlib import asynccontextmanager
from typing import Callable, AsyncContextManager

_DEF_URL = os.getenv("SESSION_REDIS_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
_tls_insecure = os.getenv("REDIS_TLS_INSECURE", "0") == "1"
redis_kwargs = {"ssl_cert_reqs": ssl.CERT_NONE} if _tls_insecure else {}


class _RedisSession:
    def __init__(self, url: str = _DEF_URL):
        self._r = aioredis.from_url(url, decode_responses=True, **redis_kwargs)

    async def setex(self, key: str, ttl: int, value: str):
        await self._r.setex(key, ttl, value)

    async def get(self, key: str):
        return await self._r.get(key)

    async def delete(self, key: str):
        """Delete a key from Redis."""
        return await self._r.delete(key)

    async def close(self):
        await self._r.close()


def factory(url: str = _DEF_URL) -> Callable[[], AsyncContextManager]:
    @asynccontextmanager
    async def _ctx():
        client = _RedisSession(url)
        try:
            yield client
        finally:
            await client.close()

    return _ctx