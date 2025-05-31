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

import os
from importlib import import_module
from typing import Callable, AsyncContextManager

__all__ = ["factory_for_env"]


def factory_for_env() -> Callable[[], AsyncContextManager]:
    """Return a session provider factory based on `$SESSION_PROVIDER`."""

    provider = os.getenv("SESSION_PROVIDER", "memory").lower()

    # Fast paths for built-ins
    if provider in ("memory", "mem", "inmemory"):
        from .providers import memory
        return memory.factory()

    if provider in ("redis", "redis_store"):
        from .providers import redis
        return redis.factory()

    # Dynamic lookup for custom providers
    mod = import_module(f"chuk_sessions.providers.{provider}")
    if not hasattr(mod, "factory"):
        raise AttributeError(
            f"Session provider '{provider}' lacks a factory() function"
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