# -*- coding: utf-8 -*-
# chuk_sessions/__init__.py
"""
CHUK Sessions - Advanced async session management with grid architecture.

Provides both low-level provider access and high-level session management
with TTL support, multi-tenant isolation, and multiple storage backends.
"""

from __future__ import annotations

# Version
__version__ = "2.0.0"

# Core imports
from .session_manager import SessionManager
from .exceptions import ProviderError, SessionError
from .provider_factory import factory_for_env
from .api import get_session, session

# Convenience imports for providers
from .providers import memory, redis

__all__ = [
    # Simple API
    "get_session",
    "session",
    
    # High-level API
    "SessionManager",
    
    # Factory
    "factory_for_env",
    
    # Exceptions
    "ProviderError",
    "SessionError",
    
    # Version
    "__version__",
]

# Module-level docstring for help()
__doc__ = """
CHUK Sessions provides advanced session management for Python applications.

Quick Start:
    >>> from chuk_sessions import get_session
    >>> async with get_session() as session:
    ...     await session.set("key", "value")
    ...     value = await session.get("key")

High-Level API:
    >>> from chuk_sessions import SessionManager
    >>> mgr = SessionManager(sandbox_id="my-app")
    >>> session_id = await mgr.allocate_session(user_id="alice")

Low-Level API:
    >>> from chuk_sessions.provider_factory import factory_for_env
    >>> async with factory_for_env() as session:
    ...     await session.set("key", "value")              # Default TTL
    ...     await session.setex("temp", 60, "expires")     # Explicit TTL
    ...     value = await session.get("key")

Environment Variables:
    SESSION_PROVIDER - Provider to use (memory, redis)
    SESSION_DEFAULT_TTL - Default TTL in seconds (default: 3600)
    SESSION_REDIS_URL - Redis connection URL
"""