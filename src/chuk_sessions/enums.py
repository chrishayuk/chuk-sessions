# -*- coding: utf-8 -*-
# chuk_sessions/enums.py
"""
Enumerations for CHUK Sessions.

This module contains all enums used throughout the library to replace magic strings
and provide type safety.
"""

from __future__ import annotations

from enum import Enum


class SessionStatus(str, Enum):
    """Session lifecycle status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    TERMINATED = "terminated"


class ProviderType(str, Enum):
    """Session storage provider types."""

    MEMORY = "memory"
    REDIS = "redis"


class TokenType(str, Enum):
    """CSRF token types."""

    HMAC = "hmac"
    DOUBLE_SUBMIT = "double_submit"
    ENCRYPTED = "encrypted"


class ProtocolType(str, Enum):
    """Session ID protocol types."""

    GENERIC = "generic"
    MCP = "mcp"
    HTTP = "http"
    WEBSOCKET = "websocket"
    JWT = "jwt"
    UUID = "uuid"
    API_KEY = "api_key"
    TEMP_TOKEN = "temp_token"


__all__ = [
    "SessionStatus",
    "ProviderType",
    "TokenType",
    "ProtocolType",
]
