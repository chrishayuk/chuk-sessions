# ===========================================================================
# tests/providers/test_memory.py
# ===========================================================================
"""Comprehensive tests for the memory session provider."""

import asyncio
import time
import pytest
from unittest.mock import patch

from chuk_sessions.providers.memory import factory, _MemorySession


class TestMemorySession:
    """Test the _MemorySession class directly."""

    @pytest.fixture
    def clear_cache(self):
        """Clear the global cache before each test."""
        _MemorySession._cache.clear()
        yield
        _MemorySession._cache.clear()

    @pytest.mark.asyncio
    async def test_setex_and_get_basic(self, clear_cache):
        """Test basic set and get operations."""
        session = _MemorySession()

        await session.setex("test_key", 60, "test_value")
        result = await session.get("test_key")

        assert result == "test_value"

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, clear_cache):
        """Test getting a key that doesn't exist."""
        session = _MemorySession()

        result = await session.get("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_ttl_expiration(self, clear_cache):
        """Test that keys expire after TTL."""
        session = _MemorySession()

        # Set with very short TTL
        await session.setex("expire_key", 1, "expire_value")

        # Should exist immediately
        result = await session.get("expire_key")
        assert result == "expire_value"

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired and cleaned up
        result = await session.get("expire_key")
        assert result is None

        # Verify key was removed from cache
        assert "expire_key" not in _MemorySession._cache

    @pytest.mark.asyncio
    async def test_overwrite_existing_key(self, clear_cache):
        """Test overwriting an existing key."""
        session = _MemorySession()

        await session.setex("overwrite_key", 60, "original_value")
        await session.setex("overwrite_key", 120, "new_value")

        result = await session.get("overwrite_key")
        assert result == "new_value"

    @pytest.mark.asyncio
    async def test_delete_existing_key(self, clear_cache):
        """Test deleting an existing key."""
        session = _MemorySession()

        await session.setex("delete_key", 60, "delete_value")

        # Delete should return True for existing key
        deleted = await session.delete("delete_key")
        assert deleted is True

        # Key should be gone
        result = await session.get("delete_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key(self, clear_cache):
        """Test deleting a key that doesn't exist."""
        session = _MemorySession()

        # Delete should return False for non-existent key
        deleted = await session.delete("nonexistent")
        assert deleted is False

    @pytest.mark.asyncio
    async def test_close_operation(self, clear_cache):
        """Test the close operation."""
        session = _MemorySession()

        # Close should not raise an exception
        await session.close()

        # Session should still work after close (no-op operation)
        await session.setex("after_close", 60, "still_works")
        result = await session.get("after_close")
        assert result == "still_works"

    @pytest.mark.asyncio
    async def test_concurrent_access(self, clear_cache):
        """Test concurrent access to the session."""
        session = _MemorySession()

        async def writer(key_suffix: str, value: str):
            await session.setex(f"concurrent_{key_suffix}", 60, value)

        async def reader(key_suffix: str) -> str:
            await asyncio.sleep(0.01)  # Small delay to test race conditions
            return await session.get(f"concurrent_{key_suffix}")

        # Start multiple writers and readers concurrently
        writers = [writer(f"key_{i}", f"value_{i}") for i in range(10)]
        readers = [reader(f"key_{i}") for i in range(10)]

        # Execute all operations
        await asyncio.gather(*writers)
        results = await asyncio.gather(*readers)

        # All values should be present
        expected = [f"value_{i}" for i in range(10)]
        assert results == expected

    @pytest.mark.asyncio
    async def test_shared_cache_between_instances(self, clear_cache):
        """Test that multiple instances share the same cache."""
        session1 = _MemorySession()
        session2 = _MemorySession()

        await session1.setex("shared_key", 60, "shared_value")
        result = await session2.get("shared_key")

        assert result == "shared_value"

    @pytest.mark.asyncio
    async def test_edge_case_zero_ttl(self, clear_cache):
        """Test edge case with zero TTL (should expire immediately)."""
        session = _MemorySession()

        await session.setex("zero_ttl", 0, "should_expire")

        # Even with zero TTL, might briefly exist due to timing
        # But should definitely be expired after a small delay
        await asyncio.sleep(0.01)
        result = await session.get("zero_ttl")

        assert result is None

    @pytest.mark.asyncio
    async def test_negative_ttl(self, clear_cache):
        """Test with negative TTL (should expire immediately)."""
        session = _MemorySession()

        await session.setex("negative_ttl", -1, "already_expired")
        result = await session.get("negative_ttl")

        assert result is None

    @pytest.mark.asyncio
    async def test_large_ttl(self, clear_cache):
        """Test with very large TTL."""
        session = _MemorySession()

        # TTL of ~31 years
        large_ttl = 60 * 60 * 24 * 365 * 31
        await session.setex("large_ttl", large_ttl, "long_lived")

        result = await session.get("large_ttl")
        assert result == "long_lived"

    @pytest.mark.asyncio
    async def test_various_value_types(self, clear_cache):
        """Test storing various string representations."""
        session = _MemorySession()

        test_cases = [
            ("empty", ""),
            ("json", '{"key": "value"}'),
            ("unicode", "🚀 测试 ñoño"),
            ("multiline", "line1\nline2\nline3"),
            ("whitespace", "  spaces  "),
            ("numbers", "12345"),
            ("special_chars", "!@#$%^&*()"),
        ]

        # Store all values
        for key, value in test_cases:
            await session.setex(f"type_{key}", 60, value)

        # Retrieve and verify all values
        for key, expected_value in test_cases:
            result = await session.get(f"type_{key}")
            assert result == expected_value, (
                f"Failed for {key}: {result} != {expected_value}"
            )


class TestMemoryFactory:
    """Test the factory function and context manager behavior."""

    @pytest.fixture
    def clear_cache(self):
        """Clear the global cache before each test."""
        _MemorySession._cache.clear()
        yield
        _MemorySession._cache.clear()

    @pytest.mark.asyncio
    async def test_factory_returns_callable(self):
        """Test that factory returns a callable."""
        session_factory = factory()
        assert callable(session_factory)

    @pytest.mark.asyncio
    async def test_context_manager_usage(self, clear_cache):
        """Test using the factory with context manager."""
        session_factory = factory()

        async with session_factory() as session:
            await session.setex("context_key", 60, "context_value")
            result = await session.get("context_key")
            assert result == "context_value"

        # After context manager, data should still persist (shared cache)
        async with session_factory() as session2:
            result = await session2.get("context_key")
            assert result == "context_value"

    @pytest.mark.asyncio
    async def test_multiple_context_managers(self, clear_cache):
        """Test multiple concurrent context managers."""
        session_factory = factory()

        async def use_session(key_suffix: str):
            async with session_factory() as session:
                await session.setex(f"multi_{key_suffix}", 60, f"value_{key_suffix}")
                return await session.get(f"multi_{key_suffix}")

        # Use multiple sessions concurrently
        results = await asyncio.gather(*[use_session(str(i)) for i in range(5)])

        expected = [f"value_{i}" for i in range(5)]
        assert results == expected

    @pytest.mark.asyncio
    async def test_exception_handling_in_context(self, clear_cache):
        """Test that exceptions don't break the context manager."""
        session_factory = factory()

        # First, set a value
        async with session_factory() as session:
            await session.setex("exception_test", 60, "before_exception")

        # Now cause an exception inside context manager
        with pytest.raises(ValueError):
            async with session_factory() as session:
                await session.setex("during_exception", 60, "test")
                raise ValueError("Test exception")

        # Data should still be accessible after exception
        async with session_factory() as session:
            result1 = await session.get("exception_test")
            result2 = await session.get("during_exception")

            assert result1 == "before_exception"
            assert result2 == "test"  # Was set before exception

    @pytest.mark.asyncio
    async def test_cleanup_on_context_exit(self, clear_cache):
        """Test that close() is called on context exit."""
        session_factory = factory()

        # Create a mock that tracks if close was called
        close_called = False
        original_close = _MemorySession.close

        async def mock_close(self):
            nonlocal close_called
            close_called = True
            return await original_close(self)

        with patch.object(_MemorySession, "close", mock_close):
            async with session_factory() as session:
                await session.setex("cleanup_test", 60, "test_value")

            # close() should have been called
            assert close_called is True


class TestMemorySessionIntegration:
    """Integration tests simulating real usage patterns."""

    @pytest.fixture
    def clear_cache(self):
        """Clear the global cache before each test."""
        _MemorySession._cache.clear()
        yield
        _MemorySession._cache.clear()

    @pytest.mark.asyncio
    async def test_session_like_usage(self, clear_cache):
        """Test usage pattern similar to web session storage."""
        session_factory = factory()

        # Simulate user login
        user_id = "user123"
        session_data = '{"user_id": "user123", "role": "admin", "login_time": "2024-01-01T10:00:00Z"}'

        async with session_factory() as session:
            # Store session with 30-minute TTL
            await session.setex(f"session:{user_id}", 1800, session_data)

        # Simulate session retrieval
        async with session_factory() as session:
            retrieved_data = await session.get(f"session:{user_id}")
            assert retrieved_data == session_data

        # Simulate session deletion (logout)
        async with session_factory() as session:
            deleted = await session.delete(f"session:{user_id}")
            assert deleted is True

            # Verify session is gone
            result = await session.get(f"session:{user_id}")
            assert result is None

    @pytest.mark.asyncio
    async def test_cache_like_usage(self, clear_cache):
        """Test usage pattern similar to application caching."""
        session_factory = factory()

        # Simulate expensive computation result caching
        cache_key = "expensive_computation:params123"
        result_data = (
            '{"computation_result": 42, "computed_at": "2024-01-01T10:00:00Z"}'
        )

        async with session_factory() as session:
            # Cache result for 5 minutes
            await session.setex(cache_key, 300, result_data)

        # Simulate cache hit
        async with session_factory() as session:
            cached_result = await session.get(cache_key)
            assert cached_result == result_data

        # Simulate cache invalidation
        async with session_factory() as session:
            await session.delete(cache_key)

            # Verify cache miss
            result = await session.get(cache_key)
            assert result is None

    @pytest.mark.asyncio
    async def test_high_concurrency_simulation(self, clear_cache):
        """Test behavior under high concurrent load."""
        session_factory = factory()
        num_operations = 100

        async def concurrent_worker(worker_id: int):
            """Simulate a worker doing multiple operations."""
            async with session_factory() as session:
                # Each worker does multiple operations
                for i in range(10):
                    key = f"worker_{worker_id}_op_{i}"
                    value = f"data_{worker_id}_{i}"

                    await session.setex(key, 60, value)
                    retrieved = await session.get(key)

                    assert retrieved == value

                    # Sometimes delete the key
                    if i % 3 == 0:
                        deleted = await session.delete(key)
                        assert deleted is True

        # Run many workers concurrently
        workers = [concurrent_worker(i) for i in range(num_operations)]
        await asyncio.gather(*workers)

        # Verify final state
        async with session_factory() as session:
            # Count remaining keys
            remaining_keys = 0
            for worker_id in range(num_operations):
                for op_id in range(10):
                    key = f"worker_{worker_id}_op_{op_id}"
                    if await session.get(key) is not None:
                        remaining_keys += 1

            # Should have some keys remaining (those not deleted)
            # Approximately 70% should remain (10 ops, delete every 3rd)
            assert remaining_keys > 0


class TestMemorySessionEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.fixture
    def clear_cache(self):
        """Clear the global cache before each test."""
        _MemorySession._cache.clear()
        yield
        _MemorySession._cache.clear()

    @pytest.mark.asyncio
    async def test_very_long_keys(self, clear_cache):
        """Test with very long key names."""
        session = _MemorySession()

        long_key = "x" * 10000  # 10KB key
        await session.setex(long_key, 60, "long_key_value")

        result = await session.get(long_key)
        assert result == "long_key_value"

    @pytest.mark.asyncio
    async def test_very_long_values(self, clear_cache):
        """Test with very long values."""
        session = _MemorySession()

        long_value = "x" * 100000  # 100KB value
        await session.setex("long_value_key", 60, long_value)

        result = await session.get("long_value_key")
        assert result == long_value

    @pytest.mark.asyncio
    async def test_special_key_characters(self, clear_cache):
        """Test with special characters in keys."""
        session = _MemorySession()

        special_keys = [
            "key:with:colons",
            "key.with.dots",
            "key-with-dashes",
            "key_with_underscores",
            "key with spaces",
            "key/with/slashes",
            "key🚀with🌟emojis",
            "",  # empty key
        ]

        for key in special_keys:
            await session.setex(key, 60, f"value_for_{key}")

        for key in special_keys:
            result = await session.get(key)
            assert result == f"value_for_{key}"

    @pytest.mark.asyncio
    async def test_time_manipulation(self, clear_cache):
        """Test behavior when system time changes."""
        session = _MemorySession()

        # Set a key with normal TTL
        await session.setex("time_test", 60, "time_value")

        # Mock time going backward (shouldn't break anything)
        with patch("time.time", return_value=time.time() - 3600):
            result = await session.get("time_test")
            # Should still work, might return the value or None depending on implementation
            assert result in ["time_value", None]

    @pytest.mark.asyncio
    async def test_memory_cleanup_on_expiration(self, clear_cache):
        """Test that expired entries are actually removed from memory."""
        session = _MemorySession()

        # Add many short-lived entries
        for i in range(100):
            await session.setex(f"cleanup_test_{i}", 1, f"value_{i}")

        # Verify they exist
        assert len(_MemorySession._cache) == 100

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Access one key to trigger cleanup
        result = await session.get("cleanup_test_0")
        assert result is None

        # Cache should be smaller now (that one key was cleaned up)
        assert len(_MemorySession._cache) < 100

        # Access all keys to trigger full cleanup
        for i in range(100):
            await session.get(f"cleanup_test_{i}")

        # All expired keys should be cleaned up
        assert len(_MemorySession._cache) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
