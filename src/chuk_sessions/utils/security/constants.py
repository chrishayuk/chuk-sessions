# -*- coding: utf-8 -*-
# chuk_sessions/utils/security/constants.py
"""
Shared constants and patterns for security utilities.

This module contains all the constants, character sets, patterns, and default
values used across the security utilities to ensure consistency and make
configuration changes easier to manage.
"""

from __future__ import annotations

import string
import re
from typing import Dict, Any, Pattern

# ─────────────────────────────────────────────────────────────────────────────
# Character Sets for Session ID Generation
# ─────────────────────────────────────────────────────────────────────────────

# Standard alphanumeric characters (safe for most contexts)
ALPHABET_ALPHANUMERIC = string.ascii_letters + string.digits

# URL-safe characters (includes hyphens and underscores)
ALPHABET_URL_SAFE = string.ascii_letters + string.digits + "-_"

# Hexadecimal characters (lowercase)
ALPHABET_HEX = string.hexdigits.lower()

# MCP spec: session ID must contain only visible ASCII (0x21 to 0x7E)
# This includes all printable ASCII except space (0x20) and DEL (0x7F)
MCP_VALID_CHARS = "".join(chr(i) for i in range(0x21, 0x7F))

# Extended character set for MCP (URL-safe plus some punctuation)
MCP_EXTENDED_CHARS = ALPHABET_URL_SAFE + "."


# ─────────────────────────────────────────────────────────────────────────────
# Session ID Format Configurations
# ─────────────────────────────────────────────────────────────────────────────

# Default session ID formats for different protocols
SESSION_ID_FORMATS: Dict[str, Dict[str, Any]] = {
    # Generic sessions (default format)
    "generic": {
        "length": 32,
        "alphabet": ALPHABET_ALPHANUMERIC,
        "prefix": "sess",
        "separator": "-",
    },
    # MCP protocol sessions
    "mcp": {
        "length": 36,
        "alphabet": MCP_EXTENDED_CHARS,
        "prefix": "mcp",
        "separator": "-",
    },
    # HTTP web application sessions
    "http": {
        "length": 32,
        "alphabet": ALPHABET_URL_SAFE,
        "prefix": "http",
        "separator": "-",
    },
    # WebSocket connection sessions
    "websocket": {
        "length": 32,
        "alphabet": ALPHABET_URL_SAFE,
        "prefix": "ws",
        "separator": "-",
    },
    # JWT token IDs (jti claim)
    "jwt": {
        "length": 0,  # Special case - uses token_urlsafe
        "alphabet": "",
        "prefix": "",
        "separator": "",
    },
    # UUID format sessions
    "uuid": {
        "length": 36,  # Standard UUID length
        "alphabet": "",  # Special case - uses uuid4()
        "prefix": "",
        "separator": "",
    },
    # API key format
    "api_key": {
        "length": 40,
        "alphabet": ALPHABET_HEX,
        "prefix": "ak",
        "separator": "_",
    },
    # Temporary token format
    "temp_token": {
        "length": 16,
        "alphabet": ALPHABET_ALPHANUMERIC,
        "prefix": "tmp",
        "separator": "_",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Security Default Values
# ─────────────────────────────────────────────────────────────────────────────

# Minimum entropy requirements
DEFAULT_MIN_ENTROPY_BITS = 128
MINIMUM_ENTROPY_BITS = 64  # Absolute minimum for any session
RECOMMENDED_ENTROPY_BITS = 128  # Recommended for production

# Session ID constraints
DEFAULT_SESSION_ID_MIN_LENGTH = 16
MINIMUM_SESSION_ID_LENGTH = 12  # Absolute minimum
MAXIMUM_SESSION_ID_LENGTH = 255  # Practical maximum

# Character diversity requirements
MIN_UNIQUE_CHARACTERS = 8  # Minimum unique characters in session ID
MIN_CHARACTER_TYPES = 2  # Minimum character types (letters, digits, etc.)

# CSRF token settings
DEFAULT_CSRF_TOKEN_MAX_AGE = 3600  # 1 hour in seconds
MINIMUM_CSRF_TOKEN_AGE = 300  # 5 minutes minimum
MAXIMUM_CSRF_TOKEN_AGE = 86400  # 24 hours maximum

# Rate limiting defaults
DEFAULT_RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
DEFAULT_RATE_LIMIT_COUNT = 1000  # Default requests per window
MINIMUM_RATE_LIMIT_WINDOW = 60  # 1 minute minimum window

# Session binding settings
SESSION_BINDING_KEY_LENGTH = 16  # Length of binding key in characters
SESSION_BINDING_TOLERANCE = 0  # No tolerance for binding mismatches by default

# Origin validation settings
LOCALHOST_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "[::1]"}
PRIVATE_IP_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


# ─────────────────────────────────────────────────────────────────────────────
# Regular Expression Patterns
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS: Dict[str, Pattern[str]] = {
    # MCP session ID patterns
    "mcp_uuid": re.compile(
        r"^mcp-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    ),
    "mcp_custom": re.compile(r"^mcp-[a-zA-Z0-9_.-]{20,}$"),
    # HTTP session patterns
    "http_session": re.compile(r"^http-[a-zA-Z0-9_-]+$"),
    "http_session_relaxed": re.compile(r"^[a-zA-Z0-9_-]+$"),
    # WebSocket session patterns
    "websocket_session": re.compile(r"^ws-[a-zA-Z0-9_-]+$"),
    # Generic patterns
    "alphanumeric": re.compile(r"^[a-zA-Z0-9]+$"),
    "url_safe": re.compile(r"^[a-zA-Z0-9_-]+$"),
    "hex_string": re.compile(r"^[a-f0-9]+$", re.IGNORECASE),
    # UUID patterns
    "uuid_v4": re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        re.IGNORECASE,
    ),
    "uuid_any": re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    ),
    # CSRF token patterns
    "csrf_token": re.compile(r"^[0-9]+:[a-zA-Z0-9+/=_-]*:[a-f0-9]{64}$"),
    # Timestamp patterns
    "unix_timestamp": re.compile(r"^[0-9]{10}$"),
    "iso_timestamp": re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})$"
    ),
    # Origin and URL patterns
    "http_origin": re.compile(r"^https?://[a-zA-Z0-9.-]+(?::[0-9]+)?$"),
    "wildcard_domain": re.compile(r"^\*\.[a-zA-Z0-9.-]+$"),
    # Security-related patterns
    "visible_ascii": re.compile(r"^[\x21-\x7E]+$"),
    "base64_urlsafe": re.compile(r"^[a-zA-Z0-9_-]+$"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Protocol-Specific Requirements
# ─────────────────────────────────────────────────────────────────────────────

# MCP protocol requirements (from spec)
MCP_REQUIREMENTS = {
    "session_id_charset": "visible_ascii",  # 0x21 to 0x7E
    "session_id_uniqueness": "global",  # Must be globally unique
    "session_id_security": "cryptographic",  # Cryptographically secure
    "origin_validation": "required",  # Must validate Origin header
    "https_localhost_exception": True,  # HTTP allowed for localhost
}

# HTTP session requirements
HTTP_REQUIREMENTS = {
    "session_id_charset": "url_safe",  # URL-safe characters
    "csrf_protection": "recommended",  # CSRF tokens recommended
    "secure_cookie": "https_only",  # Secure flag for HTTPS
    "httponly_cookie": True,  # HttpOnly flag recommended
    "samesite_cookie": "strict",  # SameSite=Strict recommended
}

# WebSocket requirements
WEBSOCKET_REQUIREMENTS = {
    "session_id_charset": "url_safe",  # URL-safe characters
    "origin_validation": "required",  # Must validate Origin
    "subprotocol_auth": "optional",  # Can use subprotocol for auth
}


# ─────────────────────────────────────────────────────────────────────────────
# Error Messages
# ─────────────────────────────────────────────────────────────────────────────

ERROR_MESSAGES = {
    # Session ID errors
    "session_id_too_short": "Session ID must be at least {min_length} characters",
    "session_id_invalid_chars": "Session ID contains invalid characters for protocol {protocol}",
    "session_id_low_entropy": "Session ID has insufficient entropy (minimum {min_bits} bits)",
    "session_id_no_diversity": "Session ID lacks character diversity (minimum {min_unique} unique characters)",
    # CSRF errors
    "csrf_token_expired": "CSRF token has expired (age: {age}s, max: {max_age}s)",
    "csrf_token_invalid": "CSRF token signature is invalid",
    "csrf_token_malformed": "CSRF token format is malformed",
    # Origin validation errors
    "origin_not_allowed": "Origin '{origin}' is not in allowed origins list",
    "origin_malformed": "Origin header is malformed or missing",
    "origin_dns_rebinding": "Origin validation failed - possible DNS rebinding attack",
    # Security context errors
    "insecure_context": "Request must be made over HTTPS",
    "localhost_only": "HTTP requests only allowed for localhost in development",
    # Rate limiting errors
    "rate_limit_exceeded": "Rate limit exceeded: {count}/{limit} requests in {window}s",
    "rate_limit_window_invalid": "Rate limit window must be between {min}s and {max}s",
    # Configuration errors
    "config_entropy_too_low": "Entropy requirement too low (minimum {min} bits)",
    "config_invalid_origins": "Invalid origin pattern: {pattern}",
    "config_negative_value": "Configuration value must be positive: {field}",
}


# ─────────────────────────────────────────────────────────────────────────────
# Feature Flags and Compatibility
# ─────────────────────────────────────────────────────────────────────────────

# Feature availability flags
FEATURES = {
    "mcp_protocol": True,
    "csrf_protection": True,
    "session_binding": True,
    "rate_limiting": True,
    "origin_validation": True,
    "secure_context_validation": True,
}

# Compatibility settings
COMPATIBILITY = {
    # Allow legacy session ID formats
    "allow_legacy_session_ids": False,
    # Allow weak entropy for testing
    "allow_weak_entropy_in_tests": False,
    # Strict MCP compliance
    "strict_mcp_compliance": True,
    # Development mode relaxations
    "development_mode": False,
}


# ─────────────────────────────────────────────────────────────────────────────
# Export commonly used constants
# ─────────────────────────────────────────────────────────────────────────────

__all__ = [
    # Character sets
    "ALPHABET_ALPHANUMERIC",
    "ALPHABET_URL_SAFE",
    "ALPHABET_HEX",
    "MCP_VALID_CHARS",
    "MCP_EXTENDED_CHARS",
    # Formats and defaults
    "SESSION_ID_FORMATS",
    "DEFAULT_MIN_ENTROPY_BITS",
    "DEFAULT_SESSION_ID_MIN_LENGTH",
    "DEFAULT_CSRF_TOKEN_MAX_AGE",
    "DEFAULT_RATE_LIMIT_WINDOW",
    # Patterns
    "PATTERNS",
    # Requirements
    "MCP_REQUIREMENTS",
    "HTTP_REQUIREMENTS",
    "WEBSOCKET_REQUIREMENTS",
    # Error messages
    "ERROR_MESSAGES",
    # Features and compatibility
    "FEATURES",
    "COMPATIBILITY",
]
