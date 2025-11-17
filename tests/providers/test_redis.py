# ===========================================================================
# tests/providers/test_redis.py
# ===========================================================================
"""Comprehensive tests for the Redis session provider."""

import asyncio
import os
import ssl
import pytest
from unittest.mock import AsyncMock, patch

# Try to import redis - skip all tests if not available
try:
    import redis.exceptions
    from chuk_sessions.providers.redis import factory, _RedisSession

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Redis not installed (optional dependency)")


class TestRedisSession:
    """Test the _RedisSession class with mocked Redis."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock_client = AsyncMock()
        mock_client.setex = AsyncMock()
        mock_client.get = AsyncMock()
        mock_client.delete = AsyncMock()
        mock_client.close = AsyncMock()
        return mock_client

    @pytest.fixture
    def redis_session(self, mock_redis):
        """Create a Redis session with mocked client."""
        with patch("redis.asyncio.from_url", return_value=mock_redis):
            session = _RedisSession("redis://localhost:6379/0")
            return session, mock_redis

    @pytest.mark.asyncio
    async def test_init_with_default_url(self):
        """Test Redis session initialization with default URL."""
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_from_url.return_value = mock_client

            _session = _RedisSession()

            # Should use default URL from environment or fallback
            mock_from_url.assert_called_once()
            call_args = mock_from_url.call_args
            assert call_args[0][0] in [
                os.getenv("SESSION_REDIS_URL"),
                os.getenv("REDIS_URL"),
                "redis://localhost:6379/0",
            ]
            assert call_args[1]["decode_responses"] is True

    @pytest.mark.asyncio
    async def test_init_with_custom_url(self):
        """Test Redis session initialization with custom URL."""
        custom_url = "redis://custom-host:6380/1"

        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_client = AsyncMock()
            mock_from_url.return_value = mock_client

            _session = _RedisSession(custom_url)

            mock_from_url.assert_called_once_with(custom_url, decode_responses=True)

    @pytest.mark.asyncio
    async def test_init_with_tls_insecure(self):
        """Test Redis session initialization with TLS insecure mode."""
        env_patch = {"REDIS_TLS_INSECURE": "1"}

        # Clear other Redis URL variables to avoid conflicts
        if "SESSION_REDIS_URL" in os.environ:
            env_patch["SESSION_REDIS_URL"] = None
        if "REDIS_URL" in os.environ:
            env_patch["REDIS_URL"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            # Need to reload the module to pick up the environment change
            import importlib
            from chuk_sessions.providers import redis as redis_module

            importlib.reload(redis_module)

            with patch("redis.asyncio.from_url") as mock_from_url:
                mock_client = AsyncMock()
                mock_from_url.return_value = mock_client

                _session = redis_module._RedisSession("rediss://localhost:6379/0")

                mock_from_url.assert_called_once()
                call_kwargs = mock_from_url.call_args[1]
                assert call_kwargs["decode_responses"] is True
                assert call_kwargs["ssl_cert_reqs"] == ssl.CERT_NONE

    @pytest.mark.asyncio
    async def test_setex_operation(self, redis_session):
        """Test the setex operation."""
        session, mock_redis = redis_session

        await session.setex("test_key", 300, "test_value")

        mock_redis.setex.assert_called_once_with("test_key", 300, "test_value")

    @pytest.mark.asyncio
    async def test_get_operation(self, redis_session):
        """Test the get operation."""
        session, mock_redis = redis_session
        mock_redis.get.return_value = "test_value"

        result = await session.get("test_key")

        mock_redis.get.assert_called_once_with("test_key")
        assert result == "test_value"

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, redis_session):
        """Test getting a key that doesn't exist."""
        session, mock_redis = redis_session
        mock_redis.get.return_value = None

        result = await session.get("nonexistent_key")

        mock_redis.get.assert_called_once_with("nonexistent_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_existing_key(self, redis_session):
        """Test deleting an existing key."""
        session, mock_redis = redis_session
        mock_redis.delete.return_value = 1  # Redis returns number of deleted keys

        result = await session.delete("test_key")

        mock_redis.delete.assert_called_once_with("test_key")
        assert result == 1

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key(self, redis_session):
        """Test deleting a key that doesn't exist."""
        session, mock_redis = redis_session
        mock_redis.delete.return_value = 0  # No keys deleted

        result = await session.delete("nonexistent_key")

        mock_redis.delete.assert_called_once_with("nonexistent_key")
        assert result == 0

    @pytest.mark.asyncio
    async def test_close_operation(self, redis_session):
        """Test the close operation."""
        session, mock_redis = redis_session

        await session.close()

        mock_redis.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_redis_connection_error(self):
        """Test handling of Redis connection errors."""
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.side_effect = redis.exceptions.ConnectionError(
                "Cannot connect to Redis"
            )

            with pytest.raises(redis.exceptions.ConnectionError):
                _RedisSession("redis://invalid-host:6379/0")

    @pytest.mark.asyncio
    async def test_redis_operation_errors(self, redis_session):
        """Test handling of Redis operation errors."""
        session, mock_redis = redis_session

        # Test setex error
        mock_redis.setex.side_effect = redis.exceptions.RedisError(
            "Redis operation failed"
        )
        with pytest.raises(redis.exceptions.RedisError):
            await session.setex("key", 300, "value")

        # Test get error
        mock_redis.get.side_effect = redis.exceptions.RedisError(
            "Redis operation failed"
        )
        with pytest.raises(redis.exceptions.RedisError):
            await session.get("key")

        # Test delete error
        mock_redis.delete.side_effect = redis.exceptions.RedisError(
            "Redis operation failed"
        )
        with pytest.raises(redis.exceptions.RedisError):
            await session.delete("key")

    @pytest.mark.asyncio
    async def test_multiple_operations_sequence(self, redis_session):
        """Test a sequence of multiple operations."""
        session, mock_redis = redis_session

        # Configure mock responses
        mock_redis.get.side_effect = [None, "value1", "value2", None]
        mock_redis.delete.return_value = 1

        # Execute sequence
        result1 = await session.get("key1")  # Should be None
        await session.setex("key1", 300, "value1")
        result2 = await session.get("key1")  # Should be "value1"

        await session.setex("key2", 600, "value2")
        result3 = await session.get("key2")  # Should be "value2"

        deleted = await session.delete("key1")
        result4 = await session.get("key1")  # Should be None after delete

        # Verify results
        assert result1 is None
        assert result2 == "value1"
        assert result3 == "value2"
        assert deleted == 1
        assert result4 is None

        # Verify call counts
        assert mock_redis.setex.call_count == 2
        assert mock_redis.get.call_count == 4
        assert mock_redis.delete.call_count == 1


class TestRedisFactory:
    """Test the factory function and context manager behavior."""

    @pytest.fixture
    def mock_redis_client(self):
        """Create a mock Redis client for factory tests."""
        mock_client = AsyncMock()
        mock_client.setex = AsyncMock()
        mock_client.get = AsyncMock()
        mock_client.delete = AsyncMock()
        mock_client.close = AsyncMock()
        return mock_client

    @pytest.mark.asyncio
    async def test_factory_returns_callable(self):
        """Test that factory returns a callable."""
        session_factory = factory()
        assert callable(session_factory)

    @pytest.mark.asyncio
    async def test_factory_with_custom_url(self):
        """Test factory with custom URL."""
        custom_url = "redis://custom-host:6380/2"
        session_factory = factory(custom_url)
        assert callable(session_factory)

    @pytest.mark.asyncio
    async def test_context_manager_usage(self, mock_redis_client):
        """Test using the factory with context manager."""
        with patch("redis.asyncio.from_url", return_value=mock_redis_client):
            session_factory = factory()

            async with session_factory() as session:
                mock_redis_client.get.return_value = "test_value"

                await session.setex("context_key", 60, "context_value")
                result = await session.get("context_key")

                assert result == "test_value"
                mock_redis_client.setex.assert_called_once_with(
                    "context_key", 60, "context_value"
                )
                mock_redis_client.get.assert_called_once_with("context_key")

            # Verify close was called on context exit
            mock_redis_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_multiple_context_managers(self, mock_redis_client):
        """Test multiple concurrent context managers."""
        with patch("redis.asyncio.from_url", return_value=mock_redis_client):
            session_factory = factory()

            async def use_session(key_suffix: str):
                async with session_factory() as session:
                    mock_redis_client.get.return_value = f"value_{key_suffix}"

                    await session.setex(
                        f"multi_{key_suffix}", 60, f"value_{key_suffix}"
                    )
                    return await session.get(f"multi_{key_suffix}")

            # Use multiple sessions concurrently
            results = await asyncio.gather(*[use_session(str(i)) for i in range(3)])

            expected = [f"value_{i}" for i in range(3)]
            assert results == expected

            # Should have created multiple client instances (one per context)
            # Each context manager creates a new _RedisSession instance
            assert mock_redis_client.close.call_count >= 3

    @pytest.mark.asyncio
    async def test_exception_handling_in_context(self, mock_redis_client):
        """Test that exceptions don't break the context manager."""
        with patch("redis.asyncio.from_url", return_value=mock_redis_client):
            session_factory = factory()

            # Test that close() is called even when exception occurs
            with pytest.raises(ValueError):
                async with session_factory() as session:
                    await session.setex("exception_test", 60, "test_value")
                    raise ValueError("Test exception")

            # close() should still have been called
            mock_redis_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_redis_connection_failure_in_context(self):
        """Test handling connection failures in context manager."""
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.side_effect = redis.exceptions.ConnectionError(
                "Cannot connect"
            )

            session_factory = factory("redis://invalid-host:6379/0")

            with pytest.raises(redis.exceptions.ConnectionError):
                async with session_factory() as _session:
                    pass  # Should fail before this point

    @pytest.mark.asyncio
    async def test_context_manager_with_redis_operations_error(self, mock_redis_client):
        """Test context manager when Redis operations fail."""
        mock_redis_client.setex.side_effect = redis.exceptions.RedisError(
            "Operation failed"
        )

        with patch("redis.asyncio.from_url", return_value=mock_redis_client):
            session_factory = factory()

            with pytest.raises(redis.exceptions.RedisError):
                async with session_factory() as session:
                    await session.setex("error_key", 60, "error_value")

            # close() should still be called despite the error
            mock_redis_client.close.assert_called_once()


class TestRedisIntegration:
    """Integration-style tests with more realistic scenarios."""

    @pytest.fixture
    def mock_redis_with_behavior(self):
        """Create a mock Redis client with realistic behavior."""
        mock_client = AsyncMock()
        storage = {}  # Simulate Redis storage

        async def mock_setex(key, ttl, value):
            storage[key] = value

        async def mock_get(key):
            return storage.get(key)

        async def mock_delete(key):
            if key in storage:
                del storage[key]
                return 1
            return 0

        mock_client.setex.side_effect = mock_setex
        mock_client.get.side_effect = mock_get
        mock_client.delete.side_effect = mock_delete
        mock_client.close = AsyncMock()

        return mock_client, storage

    @pytest.mark.asyncio
    async def test_session_workflow_simulation(self, mock_redis_with_behavior):
        """Test a realistic session management workflow."""
        mock_client, storage = mock_redis_with_behavior

        with patch("redis.asyncio.from_url", return_value=mock_client):
            session_factory = factory()

            # Simulate user login session
            user_id = "user123"
            session_data = '{"user_id": "user123", "role": "admin"}'

            async with session_factory() as session:
                # Store session
                await session.setex(f"session:{user_id}", 1800, session_data)

                # Verify session exists
                retrieved = await session.get(f"session:{user_id}")
                assert retrieved == session_data

                # Update session
                updated_data = (
                    '{"user_id": "user123", "role": "admin", "last_seen": "2024-01-01"}'
                )
                await session.setex(f"session:{user_id}", 1800, updated_data)

                # Verify update
                retrieved = await session.get(f"session:{user_id}")
                assert retrieved == updated_data

                # Simulate logout (delete session)
                deleted = await session.delete(f"session:{user_id}")
                assert deleted == 1

                # Verify session is gone
                result = await session.get(f"session:{user_id}")
                assert result is None

    @pytest.mark.asyncio
    async def test_cache_behavior_simulation(self, mock_redis_with_behavior):
        """Test cache-like behavior with Redis session."""
        mock_client, storage = mock_redis_with_behavior

        with patch("redis.asyncio.from_url", return_value=mock_client):
            session_factory = factory()

            async with session_factory() as session:
                # Cache some computed results
                cache_entries = [
                    ("cache:expensive_calc:123", '{"result": 42}'),
                    (
                        "cache:user_data:456",
                        '{"name": "John", "email": "john@example.com"}',
                    ),
                    ("cache:config:app", '{"theme": "dark", "notifications": true}'),
                ]

                # Store all cache entries
                for key, value in cache_entries:
                    await session.setex(key, 300, value)

                # Verify all entries exist
                for key, expected_value in cache_entries:
                    result = await session.get(key)
                    assert result == expected_value

                # Simulate cache invalidation (delete some entries)
                await session.delete("cache:user_data:456")

                # Verify specific entry is gone but others remain
                assert await session.get("cache:user_data:456") is None
                assert await session.get("cache:expensive_calc:123") == '{"result": 42}'
                assert (
                    await session.get("cache:config:app")
                    == '{"theme": "dark", "notifications": true}'
                )

    @pytest.mark.asyncio
    async def test_concurrent_sessions(self, mock_redis_with_behavior):
        """Test multiple concurrent sessions accessing the same Redis."""
        mock_client, storage = mock_redis_with_behavior

        with patch("redis.asyncio.from_url", return_value=mock_client):
            session_factory = factory()

            async def worker_session(worker_id: int):
                async with session_factory() as session:
                    # Each worker stores and retrieves its own data
                    key = f"worker:{worker_id}"
                    value = f"data_from_worker_{worker_id}"

                    await session.setex(key, 60, value)
                    retrieved = await session.get(key)

                    assert retrieved == value
                    return retrieved

            # Run multiple workers concurrently
            num_workers = 10
            results = await asyncio.gather(
                *[worker_session(i) for i in range(num_workers)]
            )

            # Verify all workers got their expected data
            expected = [f"data_from_worker_{i}" for i in range(num_workers)]
            assert results == expected

            # Verify all data is in storage
            for i in range(num_workers):
                assert storage[f"worker:{i}"] == f"data_from_worker_{i}"


class TestRedisConfigurationAndEnvironment:
    """Test configuration handling and environment variable behavior."""

    @pytest.mark.asyncio
    async def test_environment_variable_precedence(self):
        """Test that environment variables are used correctly."""
        # Test SESSION_REDIS_URL takes precedence
        test_url = "redis://session-host:6379/1"

        # Clear the TLS insecure flag and set SESSION_REDIS_URL
        env_patch = {"SESSION_REDIS_URL": test_url, "REDIS_TLS_INSECURE": "0"}

        # Also clear REDIS_URL to avoid conflicts
        if "REDIS_URL" in os.environ:
            env_patch["REDIS_URL"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            # Need to reload module to pick up environment changes
            import importlib
            from chuk_sessions.providers import redis as redis_module

            importlib.reload(redis_module)

            with patch("redis.asyncio.from_url") as mock_from_url:
                mock_from_url.return_value = AsyncMock()

                _session = redis_module._RedisSession()  # Should use SESSION_REDIS_URL

                mock_from_url.assert_called_once_with(test_url, decode_responses=True)

    @pytest.mark.asyncio
    async def test_redis_url_fallback(self):
        """Test fallback to REDIS_URL when SESSION_REDIS_URL is not set."""
        test_url = "redis://fallback-host:6379/2"

        # Use None to actually remove the environment variable
        env_patch = {"REDIS_URL": test_url, "REDIS_TLS_INSECURE": "0"}

        # Remove SESSION_REDIS_URL if it exists
        if "SESSION_REDIS_URL" in os.environ:
            env_patch["SESSION_REDIS_URL"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            # Need to reload module to pick up environment changes
            import importlib
            from chuk_sessions.providers import redis as redis_module

            importlib.reload(redis_module)

            with patch("redis.asyncio.from_url") as mock_from_url:
                mock_from_url.return_value = AsyncMock()

                _session = redis_module._RedisSession()

                mock_from_url.assert_called_once_with(test_url, decode_responses=True)

    @pytest.mark.asyncio
    async def test_default_url_fallback(self):
        """Test default URL when no environment variables are set."""
        # Clear both environment variables by setting them to None
        env_patch = {"REDIS_TLS_INSECURE": "0"}

        # Remove both SESSION_REDIS_URL and REDIS_URL if they exist
        if "SESSION_REDIS_URL" in os.environ:
            env_patch["SESSION_REDIS_URL"] = None
        if "REDIS_URL" in os.environ:
            env_patch["REDIS_URL"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            # Need to reload module to pick up environment changes
            import importlib
            from chuk_sessions.providers import redis as redis_module

            importlib.reload(redis_module)

            with patch("redis.asyncio.from_url") as mock_from_url:
                mock_from_url.return_value = AsyncMock()

                _session = redis_module._RedisSession()

                # Should use default URL
                mock_from_url.assert_called_once_with(
                    "redis://localhost:6379/0", decode_responses=True
                )

    @pytest.mark.asyncio
    async def test_ssl_configuration(self):
        """Test SSL configuration handling."""
        # Test with TLS insecure mode disabled (default)
        env_patch = {"REDIS_TLS_INSECURE": "0"}

        # Clear other Redis URL variables to avoid conflicts
        if "SESSION_REDIS_URL" in os.environ:
            env_patch["SESSION_REDIS_URL"] = None
        if "REDIS_URL" in os.environ:
            env_patch["REDIS_URL"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            import importlib
            from chuk_sessions.providers import redis as redis_module

            importlib.reload(redis_module)

            with patch("redis.asyncio.from_url") as mock_from_url:
                mock_from_url.return_value = AsyncMock()

                _session = redis_module._RedisSession("rediss://localhost:6379/0")

                # Should not include ssl_cert_reqs
                call_kwargs = mock_from_url.call_args[1]
                assert "ssl_cert_reqs" not in call_kwargs

    @pytest.mark.asyncio
    async def test_decode_responses_always_enabled(self):
        """Test that decode_responses is always set to True."""
        with patch("redis.asyncio.from_url") as mock_from_url:
            mock_from_url.return_value = AsyncMock()

            _session = _RedisSession("redis://localhost:6379/0")

            mock_from_url.assert_called_once()
            call_kwargs = mock_from_url.call_args[1]
            assert call_kwargs["decode_responses"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
