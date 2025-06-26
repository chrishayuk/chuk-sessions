# -*- coding: utf-8 -*-
# chuk_sessions/utils/security.py
"""
Security utilities for session management.

Provides cryptographically secure session ID generation, validation,
and security helpers that comply with various protocol requirements
including MCP, HTTP security best practices, and general session security.
"""

from __future__ import annotations

import secrets
import string
import uuid
import hmac
import hashlib
import time
import re
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse

__all__ = [
    "generate_secure_session_id",
    "validate_session_id_format", 
    "generate_csrf_token",
    "validate_csrf_token",
    "validate_origin",
    "is_secure_context",
    "SessionSecurityConfig",
]

# Constants for session ID generation
_ALPHABET_ALPHANUMERIC = string.ascii_letters + string.digits
_ALPHABET_URL_SAFE = string.ascii_letters + string.digits + "-_"
_ALPHABET_HEX = string.hexdigits.lower()

# MCP spec: session ID must contain only visible ASCII (0x21 to 0x7E)
_MCP_VALID_CHARS = "".join(chr(i) for i in range(0x21, 0x7F))

# Default session ID formats for different protocols
_SESSION_ID_FORMATS = {
    "generic": {"length": 32, "alphabet": _ALPHABET_ALPHANUMERIC, "prefix": "sess"},
    "mcp": {"length": 36, "alphabet": _ALPHABET_URL_SAFE + ".", "prefix": "mcp"},
    "http": {"length": 32, "alphabet": _ALPHABET_URL_SAFE, "prefix": "http"},
    "websocket": {"length": 32, "alphabet": _ALPHABET_URL_SAFE, "prefix": "ws"},
    "jwt": {"length": 0, "alphabet": "", "prefix": ""},  # Special case for JWT
    "uuid": {"length": 36, "alphabet": "", "prefix": ""},  # Special case for UUID
}


class SessionSecurityConfig:
    """Configuration for session security settings."""
    
    def __init__(
        self,
        require_secure_transport: bool = True,
        allowed_origins: Optional[list[str]] = None,
        csrf_protection: bool = True,
        session_id_entropy_bits: int = 128,
        max_session_age_hours: int = 24,
        require_session_binding: bool = False,
        rate_limit_per_ip: Optional[int] = None,
    ):
        """
        Initialize session security configuration.
        
        Args:
            require_secure_transport: Require HTTPS for session operations
            allowed_origins: List of allowed origins for CORS/DNS rebinding protection
            csrf_protection: Enable CSRF token generation and validation
            session_id_entropy_bits: Minimum entropy for session IDs (default 128 bits)
            max_session_age_hours: Maximum session lifetime
            require_session_binding: Bind sessions to IP/User-Agent (reduces mobility)
            rate_limit_per_ip: Maximum sessions per IP address
        """
        self.require_secure_transport = require_secure_transport
        self.allowed_origins = allowed_origins or []
        self.csrf_protection = csrf_protection
        self.session_id_entropy_bits = session_id_entropy_bits
        self.max_session_age_hours = max_session_age_hours
        self.require_session_binding = require_session_binding
        self.rate_limit_per_ip = rate_limit_per_ip


def generate_secure_session_id(
    protocol: str = "generic",
    custom_format: Optional[Dict[str, Any]] = None,
    include_timestamp: bool = False,
) -> str:
    """
    Generate a cryptographically secure session ID.
    
    Uses the system's cryptographically secure random number generator
    and follows best practices for session ID generation including
    sufficient entropy and protocol-specific format requirements.
    
    Args:
        protocol: Protocol type (generic, mcp, http, websocket, jwt, uuid)
        custom_format: Override default format with {length, alphabet, prefix}
        include_timestamp: Include timestamp component for debugging/tracing
        
    Returns:
        Cryptographically secure session ID
        
    Raises:
        ValueError: If protocol is unknown or custom format is invalid
        
    Examples:
        >>> generate_secure_session_id("mcp")
        'mcp-a1b2c3d4-e5f6-7890-abcd-ef1234567890'
        
        >>> generate_secure_session_id("http")
        'http-X9zK2mN8qP4vR7sT5wY1uC3eI6oL9rE2'
        
        >>> generate_secure_session_id("uuid")
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'
    """
    # Handle special cases first
    if protocol == "uuid":
        return str(uuid.uuid4())
    
    if protocol == "jwt":
        # For JWT, we generate a random jti (JWT ID) claim
        return secrets.token_urlsafe(32)
    
    # Get format configuration
    if custom_format:
        format_config = custom_format
    elif protocol in _SESSION_ID_FORMATS:
        format_config = _SESSION_ID_FORMATS[protocol].copy()
    else:
        raise ValueError(f"Unknown protocol '{protocol}'. Use 'generic' or provide custom_format.")
    
    # Extract format parameters
    length = format_config.get("length", 32)
    alphabet = format_config.get("alphabet", _ALPHABET_ALPHANUMERIC)
    prefix = format_config.get("prefix", "")
    
    # Validate format
    if length < 16:
        raise ValueError("Session ID length must be at least 16 characters for security")
    
    if len(alphabet) < 16:
        raise ValueError("Alphabet must contain at least 16 characters for sufficient entropy")
    
    # Generate the random component
    random_part = "".join(secrets.choice(alphabet) for _ in range(length))
    
    # Build session ID
    parts = []
    
    if prefix:
        parts.append(prefix)
    
    if include_timestamp:
        # Add timestamp for debugging (not for security)
        timestamp = hex(int(time.time()))[2:]  # Remove '0x' prefix
        parts.append(timestamp)
    
    parts.append(random_part)
    
    session_id = "-".join(parts)
    
    # Validate for MCP compliance if needed
    if protocol == "mcp":
        if not validate_session_id_format(session_id, protocol="mcp"):
            # Fallback to UUID if our generated ID doesn't meet MCP requirements
            return f"mcp-{uuid.uuid4()}"
    
    return session_id


def validate_session_id_format(
    session_id: str,
    protocol: str = "generic",
    min_entropy_bits: int = 128,
) -> bool:
    """
    Validate session ID format and security properties.
    
    Checks that session IDs meet security requirements including
    sufficient length, character set restrictions, and entropy estimates.
    
    Args:
        session_id: Session ID to validate
        protocol: Expected protocol (affects character set validation)
        min_entropy_bits: Minimum entropy requirement in bits
        
    Returns:
        True if session ID format is valid and secure
        
    Examples:
        >>> validate_session_id_format("mcp-a1b2c3d4-e5f6-7890-abcd-ef1234567890", "mcp")
        True
        
        >>> validate_session_id_format("weak123", "generic")
        False
    """
    if not session_id or not isinstance(session_id, str):
        return False
    
    # Basic length check
    if len(session_id) < 16:
        return False
    
    # Protocol-specific validation
    if protocol == "mcp":
        # MCP spec: only visible ASCII characters (0x21 to 0x7E)
        if not all(0x21 <= ord(c) <= 0x7E for c in session_id):
            return False
        
        # Additional MCP security: should be globally unique and cryptographically secure
        # We expect either a UUID format or our generated format
        uuid_pattern = re.compile(r'^mcp-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        custom_pattern = re.compile(r'^mcp-[a-zA-Z0-9_.-]{20,}$')
        
        if not (uuid_pattern.match(session_id) or custom_pattern.match(session_id)):
            return False
    
    elif protocol == "http":
        # HTTP sessions: URL-safe characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', session_id.split('-', 1)[-1]):
            return False
    
    elif protocol == "websocket":
        # WebSocket: similar to HTTP but may have different requirements
        if not re.match(r'^[a-zA-Z0-9_-]+$', session_id.split('-', 1)[-1]):
            return False
    
    # Entropy estimation (simplified)
    # This is a rough estimate based on character set size and length
    unique_chars = len(set(session_id))
    if unique_chars < 8:  # Too little character diversity
        return False
    
    # Estimate entropy: log2(charset_size) * length
    # This is conservative - real entropy may be higher
    charset_size = len(_ALPHABET_ALPHANUMERIC)  # Conservative estimate
    estimated_entropy = len(session_id) * (charset_size.bit_length() - 1)
    
    return estimated_entropy >= min_entropy_bits


def generate_csrf_token(session_id: str, secret_key: str, timestamp: Optional[int] = None) -> str:
    """
    Generate a CSRF token tied to a session.
    
    Creates a cryptographically secure CSRF token that is tied to the session ID
    and can be validated to prevent CSRF attacks.
    
    Args:
        session_id: Session ID to bind token to
        secret_key: Server secret key for HMAC
        timestamp: Unix timestamp (defaults to current time)
        
    Returns:
        CSRF token string
    """
    if timestamp is None:
        timestamp = int(time.time())
    
    # Create message to sign: session_id:timestamp
    message = f"{session_id}:{timestamp}"
    
    # Generate HMAC signature
    signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Combine timestamp and signature
    token = f"{timestamp}:{signature}"
    
    return token


def validate_csrf_token(
    token: str,
    session_id: str,
    secret_key: str,
    max_age_seconds: int = 3600,
) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: CSRF token to validate
        session_id: Expected session ID
        secret_key: Server secret key for HMAC verification
        max_age_seconds: Maximum age of token in seconds
        
    Returns:
        True if token is valid and not expired
    """
    try:
        # Parse token
        timestamp_str, signature = token.split(':', 1)
        timestamp = int(timestamp_str)
        
        # Check age
        current_time = int(time.time())
        if current_time - timestamp > max_age_seconds:
            return False
        
        # Regenerate expected signature
        message = f"{session_id}:{timestamp}"
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(signature, expected_signature)
        
    except (ValueError, IndexError):
        return False


def validate_origin(
    origin: str,
    allowed_origins: list[str],
    allow_localhost: bool = True,
) -> bool:
    """
    Validate Origin header to prevent DNS rebinding attacks.
    
    Critical for MCP Streamable HTTP transport and general web security.
    Per MCP spec: "Servers MUST validate the Origin header on all incoming 
    connections to prevent DNS rebinding attacks."
    
    Args:
        origin: Origin header value from request
        allowed_origins: List of allowed origin patterns
        allow_localhost: Whether to allow localhost origins for development
        
    Returns:
        True if origin is allowed
    """
    if not origin:
        return False
    
    try:
        parsed = urlparse(origin)
        
        # Check for exact matches first
        if origin in allowed_origins:
            return True
        
        # Allow localhost for development
        if allow_localhost:
            if parsed.hostname in ('localhost', '127.0.0.1', '::1'):
                return True
        
        # Pattern matching for wildcards
        for pattern in allowed_origins:
            if pattern.startswith('*.'):
                # Wildcard subdomain
                domain = pattern[2:]
                if parsed.hostname and parsed.hostname.endswith('.' + domain):
                    return True
                if parsed.hostname == domain:
                    return True
            elif pattern == origin:
                return True
        
        return False
        
    except Exception:
        return False


def is_secure_context(
    scheme: str,
    host: str,
    require_https: bool = True,
) -> bool:
    """
    Check if the request context is secure.
    
    Args:
        scheme: URL scheme (http, https)
        host: Host header value
        require_https: Whether to require HTTPS
        
    Returns:
        True if context is considered secure
    """
    # HTTPS is always secure
    if scheme == 'https':
        return True
    
    # HTTP may be acceptable in certain contexts
    if not require_https:
        return True
    
    # Localhost over HTTP is acceptable for development
    if scheme == 'http':
        parsed_host = host.split(':')[0]  # Remove port
        if parsed_host in ('localhost', '127.0.0.1', '::1'):
            return True
    
    return False


def generate_session_binding_key(
    session_id: str,
    ip_address: str,
    user_agent: str,
    secret_key: str,
) -> str:
    """
    Generate a session binding key for additional security.
    
    Creates a hash that binds the session to client characteristics.
    This can help detect session hijacking but reduces session mobility.
    
    Args:
        session_id: Session identifier
        ip_address: Client IP address
        user_agent: Client User-Agent header
        secret_key: Server secret for key derivation
        
    Returns:
        Session binding key
    """
    # Combine client characteristics
    binding_data = f"{session_id}:{ip_address}:{user_agent}"
    
    # Generate binding key
    binding_key = hmac.new(
        secret_key.encode('utf-8'),
        binding_data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()[:16]  # Truncate for storage efficiency
    
    return binding_key


def validate_session_binding(
    session_id: str,
    stored_binding_key: str,
    current_ip: str,
    current_user_agent: str,
    secret_key: str,
) -> bool:
    """
    Validate session binding to detect potential hijacking.
    
    Args:
        session_id: Session identifier
        stored_binding_key: Previously stored binding key
        current_ip: Current client IP
        current_user_agent: Current User-Agent
        secret_key: Server secret for key derivation
        
    Returns:
        True if binding is valid
    """
    expected_key = generate_session_binding_key(
        session_id, current_ip, current_user_agent, secret_key
    )
    
    return hmac.compare_digest(stored_binding_key, expected_key)


# Utility function for rate limiting (basic implementation)
def check_rate_limit(
    identifier: str,
    limit: int,
    window_seconds: int,
    storage: Optional[Dict[str, list]] = None,
) -> Tuple[bool, int]:
    """
    Simple in-memory rate limiting check.
    
    Args:
        identifier: Unique identifier (IP, user ID, etc.)
        limit: Maximum requests per window
        window_seconds: Time window in seconds
        storage: Optional storage dict (uses module-level if None)
        
    Returns:
        Tuple of (allowed, remaining_quota)
    """
    if storage is None:
        # Use module-level storage for simplicity
        # In production, use Redis or proper rate limiting service
        if not hasattr(check_rate_limit, '_storage'):
            check_rate_limit._storage = {}
        storage = check_rate_limit._storage
    
    current_time = time.time()
    window_start = current_time - window_seconds
    
    # Clean old entries and count current window
    if identifier in storage:
        storage[identifier] = [
            timestamp for timestamp in storage[identifier]
            if timestamp > window_start
        ]
    else:
        storage[identifier] = []
    
    current_count = len(storage[identifier])
    
    if current_count >= limit:
        return False, 0
    
    # Add current request
    storage[identifier].append(current_time)
    remaining = limit - (current_count + 1)
    
    return True, remaining