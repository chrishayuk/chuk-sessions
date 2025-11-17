# ===========================================================================
# tests/test_provider_factory.py
# ===========================================================================
"""Comprehensive tests for the session provider factory."""

import os
import pytest
from unittest.mock import patch, Mock, AsyncMock
from types import ModuleType

from chuk_sessions.provider_factory import factory_for_env

# Check if redis is available
try:
    import redis  # noqa: F401

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class TestProviderFactory:
    """Test the main factory_for_env function."""

    def setup_method(self):
        """Reset any cached modules before each test."""
        # Clear any cached imports
        import sys

        modules_to_clear = [
            name
            for name in sys.modules.keys()
            if name.startswith("chuk_sessions.providers")
        ]
        for module_name in modules_to_clear:
            if module_name in sys.modules:
                del sys.modules[module_name]

    @pytest.mark.asyncio
    async def test_default_memory_provider(self):
        """Test that memory provider is used by default."""
        # Clear SESSION_PROVIDER to test default
        env_patch = {}
        if "SESSION_PROVIDER" in os.environ:
            env_patch["SESSION_PROVIDER"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            with patch("chuk_sessions.providers.memory.factory") as mock_factory:
                mock_context_manager_factory = Mock()
                mock_factory.return_value = mock_context_manager_factory

                result = factory_for_env()

                mock_factory.assert_called_once()
                assert result == mock_context_manager_factory

    @pytest.mark.asyncio
    async def test_explicit_memory_provider(self):
        """Test explicit memory provider selection."""
        test_cases = ["memory", "mem", "inmemory", "MEMORY", "MEM", "INMEMORY"]

        for provider_name in test_cases:
            with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
                with patch("chuk_sessions.providers.memory.factory") as mock_factory:
                    mock_context_manager_factory = Mock()
                    mock_factory.return_value = mock_context_manager_factory

                    result = factory_for_env()

                    mock_factory.assert_called_once()
                    assert result == mock_context_manager_factory

    @pytest.mark.asyncio
    async def test_redis_provider(self):
        """Test Redis provider selection."""
        test_cases = ["redis", "redis_store", "REDIS", "REDIS_STORE"]

        for provider_name in test_cases:
            with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
                with patch("chuk_sessions.providers.redis.factory") as mock_factory:
                    mock_context_manager_factory = Mock()
                    mock_factory.return_value = mock_context_manager_factory

                    result = factory_for_env()

                    mock_factory.assert_called_once()
                    assert result == mock_context_manager_factory

    @pytest.mark.asyncio
    async def test_dynamic_provider_loading(self):
        """Test dynamic loading of custom providers."""
        provider_name = "custom_provider"

        # Create a mock module with factory function
        mock_module = Mock(spec=ModuleType)
        mock_factory_func = Mock()
        mock_context_manager_factory = Mock()
        mock_factory_func.return_value = mock_context_manager_factory
        mock_module.factory = mock_factory_func

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module", return_value=mock_module
            ) as mock_import:
                result = factory_for_env()

                mock_import.assert_called_once_with(
                    f"chuk_sessions.providers.{provider_name}"
                )
                mock_factory_func.assert_called_once()
                assert result == mock_context_manager_factory

    @pytest.mark.asyncio
    async def test_dynamic_provider_factory_is_already_factory(self):
        """Test dynamic provider where factory() returns the factory function directly."""
        provider_name = "direct_factory_provider"

        # Create a mock module where factory IS the factory function
        mock_module = Mock(spec=ModuleType)
        mock_direct_factory = Mock()
        mock_module.factory = mock_direct_factory

        # Make the factory function raise TypeError when called (it's already the factory)
        mock_direct_factory.side_effect = TypeError("Already a factory")

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module", return_value=mock_module
            ):
                result = factory_for_env()

                # Should return the factory function directly after TypeError
                assert result == mock_direct_factory

    @pytest.mark.asyncio
    async def test_dynamic_provider_non_callable_factory(self):
        """Test dynamic provider with non-callable factory attribute."""
        provider_name = "non_callable_provider"

        # Create a mock module with non-callable factory
        mock_module = Mock(spec=ModuleType)
        mock_module.factory = "not_callable"  # String instead of function

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module", return_value=mock_module
            ):
                result = factory_for_env()

                # Should return the non-callable factory directly
                assert result == "not_callable"

    @pytest.mark.asyncio
    async def test_dynamic_provider_missing_module(self):
        """Test error handling when dynamic provider module doesn't exist."""
        provider_name = "nonexistent_provider"

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module",
                side_effect=ModuleNotFoundError(
                    "No module named 'chuk_sessions.providers.nonexistent_provider'"
                ),
            ):
                with pytest.raises(
                    ModuleNotFoundError,
                    match="No module named 'chuk_sessions.providers.nonexistent_provider'",
                ):
                    factory_for_env()

    @pytest.mark.asyncio
    async def test_dynamic_provider_missing_factory_attribute(self):
        """Test error handling when dynamic provider lacks factory() function."""
        provider_name = "no_factory_provider"

        # Create a mock module without factory attribute
        mock_module = Mock(spec=ModuleType)
        del mock_module.factory  # Remove factory attribute

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module", return_value=mock_module
            ):
                with pytest.raises(
                    AttributeError, match="lacks a factory\\(\\) function"
                ):
                    factory_for_env()

    @pytest.mark.asyncio
    async def test_case_insensitive_provider_names(self):
        """Test that provider names are case-insensitive."""
        test_cases = [
            ("Memory", "memory"),
            ("REDIS", "redis"),
            ("MeM", "memory"),
            ("Redis_Store", "redis"),
            ("INMEMORY", "memory"),
        ]

        for input_name, expected_type in test_cases:
            with patch.dict(os.environ, {"SESSION_PROVIDER": input_name}):
                if expected_type == "memory":
                    with patch(
                        "chuk_sessions.providers.memory.factory"
                    ) as mock_factory:
                        mock_factory.return_value = Mock()
                        factory_for_env()
                        mock_factory.assert_called_once()
                elif expected_type == "redis":
                    with patch("chuk_sessions.providers.redis.factory") as mock_factory:
                        mock_factory.return_value = Mock()
                        factory_for_env()
                        mock_factory.assert_called_once()

    @pytest.mark.asyncio
    async def test_whitespace_handling(self):
        """Test handling of provider names with whitespace."""
        test_cases = ["  memory  ", "\tmemory\n", " redis ", "\tredis_store\n"]

        for provider_name in test_cases:
            with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
                # Should work despite whitespace (though .lower() doesn't strip whitespace)
                # This test verifies current behavior
                provider_name_clean = provider_name.lower()

                if provider_name_clean.strip() in ("memory", "mem", "inmemory"):
                    # Will try dynamic loading due to whitespace
                    with patch(
                        "chuk_sessions.provider_factory.import_module",
                        side_effect=ModuleNotFoundError(),
                    ):
                        with pytest.raises(ModuleNotFoundError):
                            factory_for_env()
                else:
                    # Will try dynamic loading
                    with patch(
                        "chuk_sessions.provider_factory.import_module",
                        side_effect=ModuleNotFoundError(),
                    ):
                        with pytest.raises(ModuleNotFoundError):
                            factory_for_env()


class TestProviderFactoryIntegration:
    """Integration tests with actual provider modules."""

    def setup_method(self):
        """Clear module cache before each test."""
        import sys

        modules_to_clear = [
            name
            for name in sys.modules.keys()
            if name.startswith("chuk_sessions.providers")
        ]
        for module_name in modules_to_clear:
            if module_name in sys.modules:
                del sys.modules[module_name]

    @pytest.mark.asyncio
    async def test_memory_provider_integration(self):
        """Test actual memory provider integration."""
        with patch.dict(os.environ, {"SESSION_PROVIDER": "memory"}):
            factory = factory_for_env()

            # Should return a callable
            assert callable(factory)

            # Should be able to create a context manager
            async with factory() as session:
                # Basic session interface should work
                await session.setex("test_key", 60, "test_value")
                result = await session.get("test_key")
                assert result == "test_value"

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not REDIS_AVAILABLE, reason="Redis not installed (optional dependency)"
    )
    async def test_redis_provider_integration(self):
        """Test Redis provider integration with mocked Redis client."""
        with patch.dict(os.environ, {"SESSION_PROVIDER": "redis"}):
            # Mock the Redis client to avoid needing actual Redis
            mock_redis_client = AsyncMock()
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.get = AsyncMock(return_value="test_value")
            mock_redis_client.close = AsyncMock()

            with patch("redis.asyncio.from_url", return_value=mock_redis_client):
                factory = factory_for_env()

                # Should return a callable
                assert callable(factory)

                # Should be able to create a context manager
                async with factory() as session:
                    # Basic session interface should work
                    await session.setex("test_key", 60, "test_value")
                    result = await session.get("test_key")
                    assert result == "test_value"

                # Verify Redis client was used
                mock_redis_client.setex.assert_called_once_with(
                    "test_key", 60, "test_value"
                )
                mock_redis_client.get.assert_called_once_with("test_key")
                mock_redis_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_provider_consistency(self):
        """Test that different provider names for same provider work consistently."""
        memory_aliases = ["memory", "mem", "inmemory"]

        # Test memory aliases
        memory_factories = []
        for alias in memory_aliases:
            with patch.dict(os.environ, {"SESSION_PROVIDER": alias}):
                factory = factory_for_env()
                memory_factories.append(factory)

        # All memory factories should work the same way
        for factory in memory_factories:
            async with factory() as session:
                await session.setex("consistency_test", 60, "memory_value")
                result = await session.get("consistency_test")
                assert result == "memory_value"

        # Test Redis aliases only if redis is available
        if REDIS_AVAILABLE:
            redis_aliases = ["redis", "redis_store"]
            mock_redis_client = AsyncMock()
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.get = AsyncMock(return_value="redis_value")
            mock_redis_client.close = AsyncMock()

            with patch("redis.asyncio.from_url", return_value=mock_redis_client):
                redis_factories = []
                for alias in redis_aliases:
                    with patch.dict(os.environ, {"SESSION_PROVIDER": alias}):
                        factory = factory_for_env()
                        redis_factories.append(factory)

                # All Redis factories should work the same way
                for factory in redis_factories:
                    async with factory() as session:
                        await session.setex("consistency_test", 60, "redis_value")
                        result = await session.get("consistency_test")
                        assert result == "redis_value"


class TestProviderFactoryEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_empty_provider_name(self):
        """Test behavior with empty provider name."""
        with patch.dict(os.environ, {"SESSION_PROVIDER": ""}):
            # Empty string should trigger dynamic loading (not built-in)
            with patch(
                "chuk_sessions.provider_factory.import_module",
                side_effect=ModuleNotFoundError("Module not found"),
            ):
                with pytest.raises(ModuleNotFoundError):
                    factory_for_env()

    @pytest.mark.asyncio
    async def test_none_provider_name(self):
        """Test behavior when SESSION_PROVIDER is unset."""
        env_patch = {}
        if "SESSION_PROVIDER" in os.environ:
            env_patch["SESSION_PROVIDER"] = None

        with patch.dict(os.environ, env_patch, clear=False):
            with patch("chuk_sessions.providers.memory.factory") as mock_factory:
                mock_factory.return_value = Mock()

                _result = factory_for_env()

                # Should default to memory
                mock_factory.assert_called_once()

    @pytest.mark.asyncio
    async def test_special_characters_in_provider_name(self):
        """Test provider names with special characters."""
        special_names = [
            "provider-with-dashes",
            "provider_with_underscores",
            "provider.with.dots",
            "provider123",
            "123provider",
        ]

        for provider_name in special_names:
            with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
                # Should attempt dynamic loading
                with patch(
                    "chuk_sessions.provider_factory.import_module",
                    side_effect=ModuleNotFoundError("Module not found"),
                ):
                    with pytest.raises(ModuleNotFoundError):
                        factory_for_env()

    @pytest.mark.asyncio
    async def test_very_long_provider_name(self):
        """Test with very long provider name."""
        long_name = "x" * 1000

        with patch.dict(os.environ, {"SESSION_PROVIDER": long_name}):
            # Should attempt dynamic loading
            with patch(
                "chuk_sessions.provider_factory.import_module",
                side_effect=ModuleNotFoundError("Module not found"),
            ):
                with pytest.raises(ModuleNotFoundError):
                    factory_for_env()

    @pytest.mark.asyncio
    async def test_unicode_provider_name(self):
        """Test provider names with Unicode characters."""
        unicode_names = [
            "provider_with_émojis",
            "测试provider",
            "provider🚀with🌟emojis",
        ]

        for provider_name in unicode_names:
            with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
                # Should attempt dynamic loading
                with patch(
                    "chuk_sessions.provider_factory.import_module",
                    side_effect=ModuleNotFoundError("Module not found"),
                ):
                    with pytest.raises(ModuleNotFoundError):
                        factory_for_env()

    @pytest.mark.asyncio
    async def test_circular_import_protection(self):
        """Test behavior when dynamic provider causes circular import."""
        provider_name = "circular_provider"

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module",
                side_effect=ImportError("Circular import detected"),
            ):
                with pytest.raises(ImportError, match="Circular import detected"):
                    factory_for_env()

    @pytest.mark.asyncio
    async def test_dynamic_provider_with_invalid_factory_signature(self):
        """Test dynamic provider where factory() has unexpected signature."""
        provider_name = "invalid_signature_provider"

        # Create a mock module with factory that requires arguments
        mock_module = Mock(spec=ModuleType)

        def factory_with_args(required_arg):
            return Mock()

        mock_module.factory = factory_with_args

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module", return_value=mock_module
            ):
                # The factory function catches TypeError and returns the function directly
                # So this should succeed and return the factory function itself
                result = factory_for_env()

                # Should return the factory function that requires args
                assert result == factory_with_args


class TestProviderFactoryEnvironmentHandling:
    """Test environment variable handling edge cases."""

    @pytest.mark.asyncio
    async def test_environment_variable_changes(self):
        """Test that environment variable changes are picked up."""
        # Start with memory
        with patch.dict(os.environ, {"SESSION_PROVIDER": "memory"}):
            with patch("chuk_sessions.providers.memory.factory") as mock_memory:
                mock_memory.return_value = Mock()

                _result1 = factory_for_env()
                mock_memory.assert_called_once()

        # Change to redis
        with patch.dict(os.environ, {"SESSION_PROVIDER": "redis"}):
            with patch("chuk_sessions.providers.redis.factory") as mock_redis:
                mock_redis.return_value = Mock()

                _result2 = factory_for_env()
                mock_redis.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_factory_calls(self):
        """Test that concurrent calls to factory_for_env work correctly."""
        import asyncio

        async def get_factory(provider_name):
            with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
                if provider_name == "memory":
                    with patch(
                        "chuk_sessions.providers.memory.factory"
                    ) as mock_factory:
                        mock_factory.return_value = Mock()
                        return factory_for_env()
                elif provider_name == "redis":
                    with patch("chuk_sessions.providers.redis.factory") as mock_factory:
                        mock_factory.return_value = Mock()
                        return factory_for_env()

        # Run multiple factory calls concurrently
        tasks = [get_factory("memory"), get_factory("redis"), get_factory("memory")]

        results = await asyncio.gather(*tasks)

        # All should succeed
        assert len(results) == 3
        assert all(result is not None for result in results)

    @pytest.mark.asyncio
    async def test_module_import_side_effects(self):
        """Test that module imports don't have unexpected side effects."""
        provider_name = "side_effect_provider"

        # Create a mock module that has side effects when imported
        mock_module = Mock(spec=ModuleType)
        side_effect_tracker = Mock()

        def import_with_side_effects(module_name):
            side_effect_tracker.side_effect_called()
            return mock_module

        mock_factory = Mock()
        mock_module.factory = mock_factory
        mock_factory.return_value = Mock()

        with patch.dict(os.environ, {"SESSION_PROVIDER": provider_name}):
            with patch(
                "chuk_sessions.provider_factory.import_module",
                side_effect=import_with_side_effects,
            ):
                _result = factory_for_env()

                # Verify the side effect was called (module was imported)
                side_effect_tracker.side_effect_called.assert_called_once()
                # Verify the factory was called
                mock_factory.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
