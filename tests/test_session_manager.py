# ===========================================================================
# tests/test_session_manager.py
# ===========================================================================
"""Comprehensive tests for SessionManager."""

import pytest
import os
from chuk_sessions.session_manager import SessionManager


class TestSessionManagerInit:
    """Test SessionManager initialization."""

    def setup_method(self):
        """Clean up environment before each test."""
        # Remove any existing sandbox IDs from environment
        for key in ["CHUK_SANDBOX_ID", "CHUK_HOST_SANDBOX_ID"]:
            if key in os.environ:
                del os.environ[key]

    def test_init_with_explicit_sandbox_id(self):
        """Test initialization with explicit sandbox ID."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        assert mgr.sandbox_id == "test-sandbox"
        assert os.environ.get("CHUK_SANDBOX_ID") == "test-sandbox"

    def test_init_with_env_sandbox_id(self):
        """Test initialization with environment variable."""
        os.environ["CHUK_SANDBOX_ID"] = "env-sandbox"
        mgr = SessionManager()
        assert mgr.sandbox_id == "env-sandbox"
        del os.environ["CHUK_SANDBOX_ID"]

    def test_init_with_auto_generated_sandbox_id(self):
        """Test initialization with auto-generated sandbox ID."""
        # Clear environment variables
        for key in ["CHUK_SANDBOX_ID", "CHUK_HOST_SANDBOX_ID"]:
            if key in os.environ:
                del os.environ[key]

        mgr = SessionManager()
        assert mgr.sandbox_id.startswith("sandbox-")
        assert len(mgr.sandbox_id) > 8

    def test_init_sets_default_ttl(self):
        """Test that default TTL is set correctly."""
        mgr = SessionManager()
        assert mgr.default_ttl_hours == 24

        mgr_custom = SessionManager(default_ttl_hours=48)
        assert mgr_custom.default_ttl_hours == 48


class TestSessionManagerLifecycle:
    """Test session lifecycle operations."""

    @pytest.mark.asyncio
    async def test_allocate_session_auto_id(self):
        """Test allocating a session with auto-generated ID."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session()

        assert session_id is not None
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    @pytest.mark.asyncio
    async def test_allocate_session_explicit_id(self):
        """Test allocating a session with explicit ID."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session(session_id="explicit-session-123")

        assert session_id == "explicit-session-123"

    @pytest.mark.asyncio
    async def test_allocate_session_with_user_id(self):
        """Test allocating a session with user ID."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session(user_id="user-123")

        # Verify session was created
        assert session_id is not None

        # Verify session info contains user_id
        info = await mgr.get_session_info(session_id)
        assert info is not None
        assert info["user_id"] == "user-123"

    @pytest.mark.asyncio
    async def test_allocate_session_with_custom_metadata(self):
        """Test allocating a session with custom metadata."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        custom_data = {"role": "admin", "permissions": ["read", "write"]}
        session_id = await mgr.allocate_session(custom_metadata=custom_data)

        info = await mgr.get_session_info(session_id)
        assert info is not None
        assert info["custom_metadata"] == custom_data

    @pytest.mark.asyncio
    async def test_validate_session_valid(self):
        """Test validating a valid session."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session()

        is_valid = await mgr.validate_session(session_id)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_validate_session_invalid(self):
        """Test validating a non-existent session."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        is_valid = await mgr.validate_session("non-existent-session")
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_delete_session(self):
        """Test deleting a session."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session()

        # Verify session exists
        assert await mgr.validate_session(session_id) is True

        # Delete session
        result = await mgr.delete_session(session_id)
        assert result is True

        # Verify session no longer exists
        assert await mgr.validate_session(session_id) is False

    @pytest.mark.asyncio
    async def test_get_session_info(self):
        """Test getting session information."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session(user_id="test-user")

        info = await mgr.get_session_info(session_id)
        assert info is not None
        assert info["session_id"] == session_id
        assert info["sandbox_id"] == "test-sandbox"
        assert info["user_id"] == "test-user"
        assert "created_at" in info
        assert "expires_at" in info
        assert info["status"] == "active"

    @pytest.mark.asyncio
    async def test_get_session_info_nonexistent(self):
        """Test getting info for nonexistent session."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        info = await mgr.get_session_info("nonexistent-session")
        assert info is None

    @pytest.mark.asyncio
    async def test_update_session_metadata_merge(self):
        """Test updating session metadata with merge."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session(
            custom_metadata={"key1": "value1", "key2": "value2"}
        )

        # Update with merge
        result = await mgr.update_session_metadata(
            session_id,
            {"key2": "new_value2", "key3": "value3"},
            merge=True,
        )
        assert result is True

        info = await mgr.get_session_info(session_id)
        assert info["custom_metadata"] == {
            "key1": "value1",
            "key2": "new_value2",
            "key3": "value3",
        }

    @pytest.mark.asyncio
    async def test_update_session_metadata_replace(self):
        """Test updating session metadata with replace."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session(
            custom_metadata={"key1": "value1", "key2": "value2"}
        )

        # Update with replace
        result = await mgr.update_session_metadata(
            session_id, {"key3": "value3"}, merge=False
        )
        assert result is True

        info = await mgr.get_session_info(session_id)
        assert info["custom_metadata"] == {"key3": "value3"}


class TestSessionManagerTTLExtension:
    """Test session TTL extension."""

    @pytest.mark.asyncio
    async def test_extend_session_ttl(self):
        """Test extending session TTL."""
        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session()

        # Extend TTL by 12 hours
        result = await mgr.extend_session_ttl(session_id, additional_hours=12)
        assert result is True

        # Verify session still exists
        assert await mgr.validate_session(session_id) is True

    @pytest.mark.asyncio
    async def test_extend_ttl_nonexistent_session(self):
        """Test extending TTL for nonexistent session."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        result = await mgr.extend_session_ttl("nonexistent-session", 12)
        assert result is False


class TestSessionManagerCacheAndStats:
    """Test cache management and statistics."""

    def test_get_cache_stats(self):
        """Test getting cache statistics."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        stats = mgr.get_cache_stats()
        assert isinstance(stats, dict)
        assert "cached_sessions" in stats
        assert "sandbox_id" in stats
        assert "default_ttl_hours" in stats
        assert stats["sandbox_id"] == "test-sandbox"
        assert stats["default_ttl_hours"] == 24

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions from cache."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        # Allocate some sessions (they won't be expired immediately)
        await mgr.allocate_session()
        await mgr.allocate_session()

        # Cleanup should return 0 as none are expired
        removed = await mgr.cleanup_expired_sessions()
        assert removed == 0


class TestSessionManagerEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_custom_session_factory(self):
        """Test initialization with custom session factory."""
        from chuk_sessions.providers.memory import factory

        custom_factory = factory()
        mgr = SessionManager(sandbox_id="test-sandbox", session_factory=custom_factory)

        # Should use the custom factory
        assert mgr.session_factory == custom_factory

        # Test that it works
        session_id = await mgr.allocate_session()
        assert session_id is not None

    @pytest.mark.asyncio
    async def test_reuse_existing_session_id(self):
        """Test reusing an existing non-expired session ID."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        # Allocate first session
        original_session = await mgr.allocate_session(
            session_id="reuse-test", user_id="user-1"
        )
        assert original_session == "reuse-test"

        # Try to allocate again with same ID - should reuse
        reused_session = await mgr.allocate_session(session_id="reuse-test")
        assert reused_session == "reuse-test"

        # Verify session info still exists
        info = await mgr.get_session_info("reuse-test")
        assert info is not None

    @pytest.mark.asyncio
    async def test_validate_session_with_error(self):
        """Test validate_session handles exceptions gracefully."""
        from unittest.mock import patch

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Mock _get_session_metadata to raise an exception
        with patch.object(
            mgr, "_get_session_metadata", side_effect=Exception("Test error")
        ):
            result = await mgr.validate_session("test-session")
            assert result is False

    @pytest.mark.asyncio
    async def test_delete_session_with_error(self):
        """Test delete_session handles exceptions gracefully."""
        from unittest.mock import patch

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Create a session first
        session_id = await mgr.allocate_session()

        # Mock the session factory to raise an exception
        original_factory = mgr.session_factory

        def failing_factory():
            raise Exception("Test error")

        with patch.object(mgr, "session_factory", failing_factory):
            result = await mgr.delete_session(session_id)
            assert result is False

        # Restore original factory
        mgr.session_factory = original_factory

    @pytest.mark.asyncio
    async def test_update_session_metadata_nonexistent(self):
        """Test updating metadata for nonexistent session."""
        mgr = SessionManager(sandbox_id="test-sandbox")

        result = await mgr.update_session_metadata("nonexistent", {"key": "value"})
        assert result is False

    @pytest.mark.asyncio
    async def test_update_session_metadata_with_error(self):
        """Test update_session_metadata handles exceptions."""
        from unittest.mock import patch

        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session()

        # Mock _store_session_metadata to raise an exception
        with patch.object(
            mgr, "_store_session_metadata", side_effect=Exception("Test error")
        ):
            result = await mgr.update_session_metadata(session_id, {"key": "value"})
            assert result is False

    @pytest.mark.asyncio
    async def test_extend_session_ttl_with_error(self):
        """Test extend_session_ttl handles exceptions."""
        from unittest.mock import patch

        mgr = SessionManager(sandbox_id="test-sandbox")
        session_id = await mgr.allocate_session()

        # Mock _get_session_metadata to raise an exception
        with patch.object(
            mgr, "_get_session_metadata", side_effect=Exception("Test error")
        ):
            result = await mgr.extend_session_ttl(session_id, 1)
            assert result is False

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions_with_expired_metadata(self):
        """Test cleanup actually removes expired sessions from cache."""
        from unittest.mock import MagicMock

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Create mock expired metadata
        expired_metadata = MagicMock()
        expired_metadata.is_expired.return_value = True

        # Add to cache
        async with mgr._cache_lock:
            mgr._session_cache["expired-1"] = expired_metadata
            mgr._session_cache["expired-2"] = expired_metadata

        # Cleanup should remove expired sessions
        removed = await mgr.cleanup_expired_sessions()
        assert removed == 2

        # Cache should be empty
        assert len(mgr._session_cache) == 0

    @pytest.mark.asyncio
    async def test_get_cached_expired_session_purged(self):
        """Test that expired sessions are purged from cache on access."""
        from unittest.mock import MagicMock

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Create mock expired metadata and add to cache
        expired_metadata = MagicMock()
        expired_metadata.is_expired.return_value = True

        async with mgr._cache_lock:
            mgr._session_cache["expired-test"] = expired_metadata

        # Try to get the session - should purge it
        result = await mgr._get_session_metadata("expired-test")

        # Should return None since it's expired
        assert result is None

        # Session should be purged from cache
        assert "expired-test" not in mgr._session_cache

    @pytest.mark.asyncio
    async def test_store_session_metadata_without_expires_at(self):
        """Test storing metadata without expires_at is handled."""

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Create metadata without expires_at
        from chuk_sessions.models import SessionMetadata

        metadata = SessionMetadata(session_id="test", sandbox_id="test-sandbox")
        metadata.expires_at = None

        # This should log warning and return without error
        await mgr._store_session_metadata(metadata)

        # No error should be raised

    @pytest.mark.asyncio
    async def test_get_session_metadata_json_error(self):
        """Test _get_session_metadata handles JSON parsing errors."""
        from unittest.mock import patch, AsyncMock

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Create a mock session that returns invalid JSON
        mock_session = AsyncMock()
        mock_session.get.return_value = "invalid-json"
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None

        with patch.object(mgr, "session_factory", return_value=mock_session):
            result = await mgr._get_session_metadata("test-session")
            # Should return None on JSON error
            assert result is None

    @pytest.mark.asyncio
    async def test_store_session_metadata_provider_error(self):
        """Test _store_session_metadata handles provider errors."""
        from unittest.mock import patch, AsyncMock
        from chuk_sessions.exceptions import SessionError

        mgr = SessionManager(sandbox_id="test-sandbox")

        # Allocate a session
        session_id = await mgr.allocate_session()

        # Get the metadata
        metadata = await mgr._get_session_metadata(session_id)

        # Mock the session factory to fail
        mock_session = AsyncMock()
        mock_session.setex.side_effect = Exception("Provider error")
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None

        with patch.object(mgr, "session_factory", return_value=mock_session):
            # Should raise SessionError
            with pytest.raises(SessionError):
                await mgr._store_session_metadata(metadata)
