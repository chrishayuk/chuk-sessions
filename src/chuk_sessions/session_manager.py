# -*- coding: utf-8 -*-
# chuk_sessions/session_manager.py
"""
Pure session manager with grid architecture support.

Simple rules:
- Always have a session (auto-allocate if needed)
- Grid paths: grid/{sandbox_id}/{session_id}/{artifact_id}
- Clean, reusable session management
- No artifact-specific logic
"""

from __future__ import annotations

import uuid
import time
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, AsyncContextManager, Callable
from dataclasses import dataclass, asdict, field

from .exceptions import SessionError

logger = logging.getLogger(__name__)

_DEFAULT_SESSION_TTL_HOURS = 24


@dataclass
class SessionMetadata:
    """Pure session metadata for grid operations."""
    session_id: str
    sandbox_id: str
    user_id: Optional[str] = None
    created_at: str = None
    expires_at: str = None
    status: str = "active"
    last_accessed: Optional[str] = None
    # Extension point for applications to add custom data
    custom_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow().isoformat() + "Z"
        if self.last_accessed is None:
            self.last_accessed = self.created_at
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        if not self.expires_at:
            return False
        expires = datetime.fromisoformat(self.expires_at.replace("Z", ""))
        return datetime.utcnow() > expires
    
    def touch(self) -> None:
        """Update last accessed time."""
        self.last_accessed = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionMetadata':
        return cls(**data)


class SessionManager:
    """
    Pure session manager with grid architecture support.
    
    Provides session lifecycle management and grid path generation
    without any application-specific logic.
    """
    
    def __init__(
        self,
        sandbox_id: str,
        session_factory: Optional[Callable[[], AsyncContextManager]] = None,
        default_ttl_hours: int = _DEFAULT_SESSION_TTL_HOURS,
    ):
        self.sandbox_id = sandbox_id
        self.default_ttl_hours = default_ttl_hours
        
        # Use provided factory or auto-detect from environment
        if session_factory:
            self.session_factory = session_factory
        else:
            from .provider_factory import factory_for_env
            self.session_factory = factory_for_env()
        
        # Simple in-memory cache for performance
        self._session_cache: Dict[str, SessionMetadata] = {}
        self._cache_lock = asyncio.Lock()
        
        logger.info(f"SessionManager initialized for sandbox: {sandbox_id}")
    
    async def allocate_session(
        self,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        ttl_hours: Optional[int] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Allocate or validate a session.
        
        Args:
            session_id: Existing session ID to validate, or None to create new
            user_id: User ID to associate with the session
            ttl_hours: Time-to-live in hours
            custom_metadata: Application-specific metadata
            
        Returns:
            Session ID (existing if valid, or newly created)
        """
        ttl_hours = ttl_hours or self.default_ttl_hours
        
        if session_id:
            # Try to validate existing session
            metadata = await self._get_session_metadata(session_id)
            if metadata and not metadata.is_expired():
                # Touch the session and update last accessed
                metadata.touch()
                await self._store_session_metadata(metadata)
                return session_id
        
        # Create new session
        if not session_id:
            session_id = self._generate_session_id(user_id)
        
        expires_at = (datetime.utcnow() + timedelta(hours=ttl_hours)).isoformat() + "Z"
        
        metadata = SessionMetadata(
            session_id=session_id,
            sandbox_id=self.sandbox_id,
            user_id=user_id,
            expires_at=expires_at,
            custom_metadata=custom_metadata or {},
        )
        
        await self._store_session_metadata(metadata)
        
        # Cache locally for performance
        async with self._cache_lock:
            self._session_cache[session_id] = metadata
        
        logger.info(f"Session allocated: {session_id} (user: {user_id})")
        return session_id
    
    async def validate_session(self, session_id: str) -> bool:
        """
        Check if session is valid and not expired.
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            True if session is valid, False otherwise
        """
        try:
            metadata = await self._get_session_metadata(session_id)
            if metadata and not metadata.is_expired():
                # Touch the session
                metadata.touch()
                await self._store_session_metadata(metadata)
                return True
            return False
        except Exception as e:
            logger.warning(f"Session validation failed for {session_id}: {e}")
            return False
    
    async def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get complete session information.
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            Session metadata dictionary or None if not found
        """
        metadata = await self._get_session_metadata(session_id)
        return metadata.to_dict() if metadata else None
    
    async def update_session_metadata(
        self, 
        session_id: str, 
        custom_metadata: Dict[str, Any],
        merge: bool = True
    ) -> bool:
        """
        Update custom metadata for a session.
        
        Args:
            session_id: Session ID to update
            custom_metadata: Custom metadata to add/update
            merge: If True, merge with existing metadata; if False, replace
            
        Returns:
            True if successful, False if session not found
        """
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
            
            # Update cache
            async with self._cache_lock:
                self._session_cache[session_id] = metadata
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update session metadata for {session_id}: {e}")
            return False
    
    async def extend_session_ttl(
        self, 
        session_id: str, 
        additional_hours: int
    ) -> bool:
        """
        Extend session TTL by additional hours.
        
        Args:
            session_id: Session ID to extend
            additional_hours: Hours to add to current expiration
            
        Returns:
            True if successful, False if session not found
        """
        try:
            metadata = await self._get_session_metadata(session_id)
            if not metadata:
                return False
            
            # Calculate new expiration
            current_expires = datetime.fromisoformat(metadata.expires_at.replace("Z", ""))
            new_expires = current_expires + timedelta(hours=additional_hours)
            metadata.expires_at = new_expires.isoformat() + "Z"
            metadata.touch()
            
            await self._store_session_metadata(metadata)
            
            # Update cache
            async with self._cache_lock:
                self._session_cache[session_id] = metadata
            
            logger.info(f"Extended session {session_id} by {additional_hours} hours")
            return True
            
        except Exception as e:
            logger.error(f"Failed to extend session TTL for {session_id}: {e}")
            return False
    
    async def delete_session(self, session_id: str) -> bool:
        """
        Delete a session completely.
        
        Args:
            session_id: Session ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        try:
            # Remove from storage
            session_ctx_mgr = self.session_factory()
            async with session_ctx_mgr as session:
                deleted = await session.delete(f"session:{session_id}")
            
            # Remove from cache
            async with self._cache_lock:
                self._session_cache.pop(session_id, None)
            
            if deleted:
                logger.info(f"Session deleted: {session_id}")
            return bool(deleted)
            
        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            return False
    
    # ─────────────────────────────────────────────────────────────────
    # Grid architecture support
    # ─────────────────────────────────────────────────────────────────
    
    def get_canonical_prefix(self, session_id: str) -> str:
        """
        Get grid path prefix for a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Grid prefix path: grid/{sandbox_id}/{session_id}/
        """
        return f"grid/{self.sandbox_id}/{session_id}/"
    
    def generate_artifact_key(self, session_id: str, artifact_id: str) -> str:
        """
        Generate complete grid artifact key.
        
        Args:
            session_id: Session ID
            artifact_id: Artifact ID
            
        Returns:
            Complete grid key: grid/{sandbox_id}/{session_id}/{artifact_id}
        """
        return f"grid/{self.sandbox_id}/{session_id}/{artifact_id}"
    
    def parse_grid_key(self, grid_key: str) -> Optional[Dict[str, str]]:
        """
        Parse a grid key back into its components.
        
        Args:
            grid_key: Complete grid key
            
        Returns:
            Dictionary with sandbox_id, session_id, artifact_id or None if invalid
        """
        parts = grid_key.split("/")
        if len(parts) >= 4 and parts[0] == "grid":
            return {
                "sandbox_id": parts[1],
                "session_id": parts[2],
                "artifact_id": parts[3] if len(parts) > 3 else None,
                "subpath": "/".join(parts[4:]) if len(parts) > 4 else None
            }
        return None
    
    def get_session_prefix_pattern(self) -> str:
        """
        Get prefix pattern for finding all sessions in this sandbox.
        
        Returns:
            Prefix pattern: grid/{sandbox_id}/
        """
        return f"grid/{self.sandbox_id}/"
    
    # ─────────────────────────────────────────────────────────────────
    # Internal methods
    # ─────────────────────────────────────────────────────────────────
    
    def _generate_session_id(self, user_id: Optional[str] = None) -> str:
        """Generate a new session ID."""
        timestamp = int(time.time())
        unique = uuid.uuid4().hex[:8]
        
        if user_id:
            # Create a safe user prefix
            safe_user = "".join(c for c in user_id if c.isalnum())[:8]
            return f"sess-{safe_user}-{timestamp}-{unique}"
        else:
            return f"sess-{timestamp}-{unique}"
    
    async def _get_session_metadata(self, session_id: str) -> Optional[SessionMetadata]:
        """Get session metadata from cache or storage."""
        # Check cache first
        async with self._cache_lock:
            if session_id in self._session_cache:
                cached = self._session_cache[session_id]
                # Verify cache entry isn't expired
                if not cached.is_expired():
                    return cached
                else:
                    # Remove expired entry from cache
                    del self._session_cache[session_id]
        
        # Query from storage
        try:
            session_ctx_mgr = self.session_factory()
            async with session_ctx_mgr as session:
                raw_data = await session.get(f"session:{session_id}")
                if raw_data:
                    data = json.loads(raw_data)
                    metadata = SessionMetadata.from_dict(data)
                    
                    # Cache it if not expired
                    if not metadata.is_expired():
                        async with self._cache_lock:
                            self._session_cache[session_id] = metadata
                        return metadata
                    else:
                        # Clean up expired session
                        await self.delete_session(session_id)
        except Exception as e:
            logger.warning(f"Failed to get session {session_id}: {e}")
        
        return None
    
    async def _store_session_metadata(self, metadata: SessionMetadata) -> None:
        """Store session metadata to storage."""
        try:
            session_ctx_mgr = self.session_factory()
            async with session_ctx_mgr as session:
                key = f"session:{metadata.session_id}"
                
                # Calculate TTL in seconds
                expires = datetime.fromisoformat(metadata.expires_at.replace("Z", ""))
                ttl_seconds = int((expires - datetime.utcnow()).total_seconds())
                
                # Don't store if already expired
                if ttl_seconds <= 0:
                    logger.warning(f"Attempted to store expired session: {metadata.session_id}")
                    return
                
                data = json.dumps(metadata.to_dict())
                await session.setex(key, ttl_seconds, data)
                
                # Update cache
                async with self._cache_lock:
                    self._session_cache[metadata.session_id] = metadata
                    
        except Exception as e:
            raise SessionError(f"Session storage failed: {e}") from e
    
    # ─────────────────────────────────────────────────────────────────
    # Administrative methods
    # ─────────────────────────────────────────────────────────────────
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from cache.
        Note: Storage provider TTL should handle storage cleanup automatically.
        
        Returns:
            Number of sessions removed from cache
        """
        cleaned = 0
        async with self._cache_lock:
            expired_keys = [
                session_id for session_id, metadata in self._session_cache.items()
                if metadata.is_expired()
            ]
            for session_id in expired_keys:
                del self._session_cache[session_id]
                cleaned += 1
        
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} expired sessions from cache")
        
        return cleaned
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        return {
            "cached_sessions": len(self._session_cache),
            "sandbox_id": self.sandbox_id,
            "default_ttl_hours": self.default_ttl_hours,
        }