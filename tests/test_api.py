# ===========================================================================
# tests/test_api.py
# ===========================================================================
"""Tests for the convenience API functions."""

import pytest
from chuk_sessions import get_session, session


class TestAPIFunctions:
    """Test the convenience API functions."""

    @pytest.mark.asyncio
    async def test_get_session_basic_usage(self):
        """Test basic usage of get_session()."""
        async with get_session() as sess:
            # Should be able to use basic session operations
            await sess.setex("test_key", 60, "test_value")
            result = await sess.get("test_key")
            assert result == "test_value"

    @pytest.mark.asyncio
    async def test_session_alias(self):
        """Test that session() is an alias for get_session()."""
        # session should be the same function as get_session
        assert session is get_session

        # Should work identically
        async with session() as sess:
            await sess.setex("alias_test", 60, "alias_value")
            result = await sess.get("alias_test")
            assert result == "alias_value"

    @pytest.mark.asyncio
    async def test_multiple_sessions(self):
        """Test that multiple sessions can be created."""
        async with get_session() as sess1:
            async with get_session() as sess2:
                await sess1.setex("sess1_key", 60, "sess1_value")
                await sess2.setex("sess2_key", 60, "sess2_value")

                # Both sessions should work independently
                # (though with memory provider they share storage)
                assert await sess1.get("sess1_key") == "sess1_value"
                assert await sess2.get("sess2_key") == "sess2_value"

    @pytest.mark.asyncio
    async def test_session_cleanup(self):
        """Test that sessions clean up properly."""
        # Create and use a session
        async with get_session() as sess:
            await sess.setex("cleanup_test", 60, "cleanup_value")
            result = await sess.get("cleanup_test")
            assert result == "cleanup_value"

        # Session should be closed after context exit
        # (we can't test this directly without inspecting internals)
