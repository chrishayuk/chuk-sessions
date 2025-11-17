# -*- coding: utf-8 -*-
# chuk_sessions/provider_factory.py
"""
Resolve the session storage back-end requested via **SESSION_PROVIDER**.

Built-in providers
──────────────────
• **memory** (default) - in-process, TTL-aware dict store
• **redis** - Redis-backed persistent session store
"""

from __future__ import annotations

import logging
import os
from importlib import import_module
from typing import AsyncContextManager, Callable

from .enums import ProviderType

logger = logging.getLogger(__name__)

__all__ = ["factory_for_env"]


def factory_for_env() -> Callable[[], AsyncContextManager]:
    """Return a session provider factory based on `$SESSION_PROVIDER`."""

    provider_str = os.getenv("SESSION_PROVIDER", ProviderType.MEMORY.value).lower()

    # Fast paths for built-ins
    if provider_str in (ProviderType.MEMORY.value, "mem", "inmemory"):
        from .providers import memory

        return memory.factory()

    if provider_str in (ProviderType.REDIS.value, "redis_store"):
        from .providers import redis

        return redis.factory()

    # Dynamic lookup for custom providers
    try:
        mod = import_module(f"chuk_sessions.providers.{provider_str}")
    except ImportError as err:
        logger.error("Failed to import provider '%s': %s", provider_str, err)
        raise

    if not hasattr(mod, "factory"):
        logger.error("Provider '%s' lacks a factory() function", provider_str)
        raise AttributeError(
            f"Session provider '{provider_str}' lacks a factory() function"
        )

    # For dynamic providers, call factory() to get the actual factory function
    factory_func = mod.factory
    if callable(factory_func):
        try:
            return factory_func()
        except TypeError:
            # If it's already the factory function, return it directly
            return factory_func
    return factory_func
