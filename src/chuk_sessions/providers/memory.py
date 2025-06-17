# ===========================================================================
# chuk_sessions/providers/memory.py
# ===========================================================================
"""Simple in-process dict with TTL support (coarse but useful for tests)."""
from __future__ import annotations

import os
import time
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Tuple, Any, Callable, AsyncContextManager

# Default TTL from environment or 1 hour
_DEFAULT_TTL = int(os.getenv("SESSION_DEFAULT_TTL", "3600"))


class _MemorySession:
    _cache: Dict[str, Tuple[Any, float]] = {}
    _LOCK = asyncio.Lock()

    async def set(self, key: str, value: str):
        """Set a key-value pair with the default TTL."""
        await self.setex(key, _DEFAULT_TTL, value)

    async def setex(self, key: str, ttl: int, value: str):
        """Set a key-value pair with explicit TTL in seconds."""
        async with _MemorySession._LOCK:
            _MemorySession._cache[key] = (value, time.time() + ttl)

    async def get(self, key: str):
        """Get a value by key, returning None if expired or missing."""
        async with _MemorySession._LOCK:
            entry = _MemorySession._cache.get(key)
            if not entry:
                return None
            value, exp = entry
            if exp < time.time():
                del _MemorySession._cache[key]
                return None
            return value

    async def delete(self, key: str):
        """Delete a key from memory cache."""
        async with _MemorySession._LOCK:
            return _MemorySession._cache.pop(key, None) is not None

    async def close(self):
        # nothing to do – kept for symmetry
        pass


def factory() -> Callable[[], AsyncContextManager]:
    @asynccontextmanager
    async def _ctx():
        client = _MemorySession()
        try:
            yield client
        finally:
            await client.close()

    return _ctx