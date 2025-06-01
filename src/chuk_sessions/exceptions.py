# -*- coding: utf-8 -*-
# chuk_sessions/exceptions.py
"""
Exception classes for sessions.
"""

from __future__ import annotations


class ProviderError(Exception):
    """Raised when the storage provider encounters an error."""
    pass


class SessionError(Exception):
    """Raised when the session provider encounters an error."""
    pass