# -*- coding: utf-8 -*-
# chuk_sessions/api.py
"""
Convenient API for CHUK Sessions.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from typing import AsyncContextManager

from .provider_factory import factory_for_env


def get_session() -> AsyncContextManager:
    """
    Get a session using the configured provider.
    
    This is a convenience wrapper around factory_for_env() that provides
    a simpler API for common use cases.
    
    Example:
        >>> from chuk_sessions import get_session
        >>> async with get_session() as session:
        ...     await session.set("key", "value")
        ...     value = await session.get("key")
    
    Returns:
        An async context manager that yields a session object
    """
    factory = factory_for_env()
    return factory()


# Alternative name for those who prefer it
session = get_session