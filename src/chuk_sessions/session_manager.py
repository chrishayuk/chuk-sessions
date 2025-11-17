# -*- coding: utf-8 -*-
# chuk_sessions/session_manager.py
"""
Pure session manager.

Simple rules:
- Always have a session (auto-allocate if needed)
- Grid paths: grid/{sandbox_id}/{session_id}/{artifact_id}
- Clean, reusable session management
- No artifact-specific logic
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncContextManager, Callable, Optional

from .exceptions import SessionError
from .models import SessionMetadata

logger = logging.getLogger(__name__)

_DEFAULT_SESSION_TTL_HOURS = 24


# ─────────────────────────────────────────────────────────────────────────────
# Backward Compatibility - Export SessionMetadata for legacy code
# ─────────────────────────────────────────────────────────────────────────────

__all__ = ["SessionManager", "SessionMetadata"]


# ─────────────────────────────────────────────────────────────────────────────
# Class: SessionManager
# ─────────────────────────────────────────────────────────────────────────────


class SessionManager:
    """
    Pure session manager with grid architecture support.

    Provides session lifecycle management plus grid-style key helpers.
    """

    def __init__(
        self,
        sandbox_id: str | None = None,
        session_factory: Optional[Callable[[], AsyncContextManager]] = None,
        default_ttl_hours: int = _DEFAULT_SESSION_TTL_HOURS,
    ) -> None:
        # 1️⃣  Determine a stable sandbox namespace
        if sandbox_id:
            self.sandbox_id = sandbox_id
        else:
            env_id = os.getenv("CHUK_SANDBOX_ID")
            cfg_id = os.getenv("CHUK_HOST_SANDBOX_ID")
            self.sandbox_id = env_id or cfg_id or f"sandbox-{uuid.uuid4().hex[:8]}"

        # make it available to downstream libs
        os.environ.setdefault("CHUK_SANDBOX_ID", self.sandbox_id)

        self.default_ttl_hours = default_ttl_hours

        # pick provider factory
        if session_factory is not None:
            self.session_factory = session_factory
        else:
            from .provider_factory import factory_for_env

            self.session_factory = factory_for_env()

        # local LRU-ish cache
        self._session_cache: dict[str, SessionMetadata] = {}
        self._cache_lock = asyncio.Lock()

        logger.debug("SessionManager initialised for sandbox: %s", self.sandbox_id)

    # ──────────────────────────────────────────────────────────────────────
    # Public API – Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    async def allocate_session(
        self,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        ttl_hours: Optional[int] = None,
        custom_metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Allocate a new session, or validate & refresh an existing one.
        """
        ttl_hours = ttl_hours or self.default_ttl_hours

        # Fast-path: try to reuse supplied ID
        if session_id:
            metadata = await self._get_session_metadata(session_id)
            if metadata and not metadata.is_expired():
                metadata.touch()
                await self._store_session_metadata(metadata)
                return session_id

        # Otherwise create new
        if not session_id:
            session_id = self._generate_session_id(user_id)

        expires_at = (
            (datetime.now(timezone.utc) + timedelta(hours=ttl_hours))
            .isoformat()
            .replace("+00:00", "Z")
        )

        metadata = SessionMetadata(
            session_id=session_id,
            sandbox_id=self.sandbox_id,
            user_id=user_id,
            expires_at=expires_at,
            custom_metadata=custom_metadata or {},
        )
        await self._store_session_metadata(metadata)

        async with self._cache_lock:
            self._session_cache[session_id] = metadata

        logger.debug("Session allocated: %s (user=%s)", session_id, user_id)
        return session_id

    async def validate_session(self, session_id: str) -> bool:
        """Return True if session is present and not expired."""
        try:
            metadata = await self._get_session_metadata(session_id)
            if metadata and not metadata.is_expired():
                metadata.touch()
                await self._store_session_metadata(metadata)
                return True
            return False
        except Exception as err:
            logger.debug("Session validation failed for %s: %s", session_id, err)
            return False

    async def get_session_info(self, session_id: str) -> Optional[dict[str, Any]]:
        """
        Get session information as a dict.

        For typed access, use get_session_metadata() instead.
        """
        metadata = await self._get_session_metadata(session_id)
        return metadata.to_dict() if metadata else None

    async def get_session_metadata(self, session_id: str) -> Optional[SessionMetadata]:
        """
        Get session information as typed SessionMetadata.

        This returns the Pydantic model directly for better type safety.
        For backwards compatibility, use get_session_info() which returns dict.
        """
        return await self._get_session_metadata(session_id)

    async def update_session_metadata(
        self,
        session_id: str,
        custom_metadata: dict[str, Any],
        merge: bool = True,
    ) -> bool:
        """Merge or overwrite the custom-metadata blob."""
        try:
            metadata = await self._get_session_metadata(session_id)
            if not metadata:
                return False

            if merge:
                metadata.custom_metadata.update(custom_metadata)
            else:
                metadata.custom_metadata = custom_metadata.copy()

            metadata.touch()
            await self._store_session_metadata(metadata)

            async with self._cache_lock:
                self._session_cache[session_id] = metadata
            return True
        except Exception as err:
            logger.error(
                "Failed to update session metadata for %s: %s", session_id, err
            )
            return False

    async def extend_session_ttl(self, session_id: str, additional_hours: int) -> bool:
        """Push the expiry farther into the future."""
        try:
            metadata = await self._get_session_metadata(session_id)
            if not metadata or not metadata.expires_at:
                return False

            current_expires = datetime.fromisoformat(
                metadata.expires_at.replace("Z", "+00:00")
            )
            new_expires = current_expires + timedelta(hours=additional_hours)
            metadata.expires_at = new_expires.isoformat().replace("+00:00", "Z")
            metadata.touch()

            await self._store_session_metadata(metadata)

            async with self._cache_lock:
                self._session_cache[session_id] = metadata
            logger.debug("Extended session %s by %dh", session_id, additional_hours)
            return True
        except Exception as err:
            logger.error("Failed to extend session TTL for %s: %s", session_id, err)
            return False

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session from provider and in-process cache."""
        try:
            session_ctx_mgr = self.session_factory()
            async with session_ctx_mgr as session:
                deleted = await session.delete(f"session:{session_id}")

            async with self._cache_lock:
                self._session_cache.pop(session_id, None)

            if deleted:
                logger.debug("Session deleted: %s", session_id)
            return bool(deleted)
        except Exception as err:
            logger.error("Failed to delete session %s: %s", session_id, err)
            return False

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    def _generate_session_id(self, user_id: Optional[str] = None) -> str:
        timestamp = int(time.time())
        rnd = uuid.uuid4().hex[:8]
        if user_id:
            safe_user = "".join(c for c in user_id if c.isalnum())[:8]
            return f"sess-{safe_user}-{timestamp}-{rnd}"
        return f"sess-{timestamp}-{rnd}"

    async def _get_session_metadata(self, session_id: str) -> Optional[SessionMetadata]:
        # Try the in-process cache first
        async with self._cache_lock:
            cached = self._session_cache.get(session_id)
            if cached and not cached.is_expired():
                return cached
            if cached and cached.is_expired():
                self._session_cache.pop(session_id, None)  # purge

        # Fallback to provider
        try:
            session_ctx_mgr = self.session_factory()
            async with session_ctx_mgr as session:
                raw = await session.get(f"session:{session_id}")
            if not raw:
                return None
            data = json.loads(raw)
            metadata = SessionMetadata.from_dict(data)
            if metadata.is_expired():
                await self.delete_session(session_id)
                return None
            # re-cache
            async with self._cache_lock:
                self._session_cache[session_id] = metadata
            return metadata
        except Exception as err:
            logger.debug("Failed fetching session %s: %s", session_id, err)
            return None

    async def _store_session_metadata(self, metadata: SessionMetadata) -> None:
        """Push the metadata blob into the provider with TTL semantics."""
        try:
            if not metadata.expires_at:
                logger.debug(
                    "Cannot store session %s without expiry", metadata.session_id
                )
                return

            session_ctx_mgr = self.session_factory()
            async with session_ctx_mgr as session:
                key = f"session:{metadata.session_id}"
                expires = datetime.fromisoformat(
                    metadata.expires_at.replace("Z", "+00:00")
                )
                ttl = int((expires - datetime.now(timezone.utc)).total_seconds())
                if ttl <= 0:  # already expired – don't store
                    logger.debug(
                        "Refusing to store expired session %s", metadata.session_id
                    )
                    return
                await session.setex(key, ttl, json.dumps(metadata.to_dict()))

            async with self._cache_lock:
                self._session_cache[metadata.session_id] = metadata
        except Exception as err:
            logger.error("Session storage failed for %s: %s", metadata.session_id, err)
            raise SessionError(f"Session storage failed: {err}") from err

    # ──────────────────────────────────────────────────────────────────────
    # Admin helpers
    # ──────────────────────────────────────────────────────────────────────

    async def cleanup_expired_sessions(self) -> int:
        """Purge expired sessions from the in-process cache."""
        removed = 0
        async with self._cache_lock:
            for sid, meta in list(self._session_cache.items()):
                if meta.is_expired():
                    self._session_cache.pop(sid, None)
                    removed += 1
        if removed:
            logger.debug("Cleaned %d expired sessions from cache", removed)
        return removed

    def get_cache_stats(self) -> dict[str, Any]:
        return {
            "cached_sessions": len(self._session_cache),
            "sandbox_id": self.sandbox_id,
            "default_ttl_hours": self.default_ttl_hours,
        }
