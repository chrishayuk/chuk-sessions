# -*- coding: utf-8 -*-
# chuk_sessions/utils/security/csrf.py
"""
CSRF (Cross-Site Request Forgery) protection utilities.

This module provides cryptographically secure CSRF token generation and validation
to prevent CSRF attacks. Tokens are tied to sessions and have configurable
expiration times. All operations use constant-time comparisons to prevent
timing attacks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Optional

from ...enums import TokenType
from ...models import CSRFTokenInfo
from .constants import (
    DEFAULT_CSRF_TOKEN_MAX_AGE,
)

__all__ = [
    "generate_csrf_token",
    "validate_csrf_token",
    "generate_double_submit_token",
    "validate_double_submit_token",
    "generate_encrypted_csrf_token",
    "validate_encrypted_csrf_token",
    "extract_csrf_token_info",
    "is_csrf_token_expired",
    "CSRFTokenInfo",
]


# ─────────────────────────────────────────────────────────────────────────────
# Basic HMAC-based CSRF Tokens
# ─────────────────────────────────────────────────────────────────────────────


def generate_csrf_token(
    session_id: str,
    secret_key: str,
    timestamp: Optional[int] = None,
    user_data: Optional[dict[str, Any]] = None,
) -> str:
    """
    Generate a CSRF token tied to a session using HMAC.

    Creates a cryptographically secure CSRF token that is tied to the session ID
    and can be validated to prevent CSRF attacks. The token includes a timestamp
    for expiration checking.

    Args:
        session_id: Session ID to bind token to
        secret_key: Server secret key for HMAC signing
        timestamp: Unix timestamp (defaults to current time)
        user_data: Optional additional data to include in token

    Returns:
        CSRF token string in format: timestamp:user_data_b64:signature

    Raises:
        ValueError: If session_id or secret_key is empty

    Examples:
        >>> token = generate_csrf_token("sess-abc123", "secret-key")
        >>> print(token)
        1703123456:e30:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

        >>> token_with_data = generate_csrf_token(
        ...     "sess-abc123",
        ...     "secret-key",
        ...     user_data={"action": "delete", "resource_id": "123"}
        ... )
    """
    if not session_id:
        raise ValueError("session_id cannot be empty")

    if not secret_key:
        raise ValueError("secret_key cannot be empty")

    if timestamp is None:
        timestamp = int(time.time())

    # Encode user data as base64 JSON
    if user_data:
        user_data_json = json.dumps(user_data, separators=(",", ":"), sort_keys=True)
        user_data_b64 = (
            base64.urlsafe_b64encode(user_data_json.encode("utf-8"))
            .decode("ascii")
            .rstrip("=")
        )
    else:
        user_data_b64 = ""

    # Create message to sign: session_id:timestamp:user_data
    message = f"{session_id}:{timestamp}:{user_data_b64}"

    # Generate HMAC signature
    signature = hmac.new(
        secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Combine timestamp, user data, and signature
    token = f"{timestamp}:{user_data_b64}:{signature}"

    return token


def validate_csrf_token(
    token: str,
    session_id: str,
    secret_key: str,
    max_age_seconds: int = DEFAULT_CSRF_TOKEN_MAX_AGE,
    require_user_data: bool = False,
) -> bool:
    """
    Validate a CSRF token.

    Args:
        token: CSRF token to validate
        session_id: Expected session ID
        secret_key: Server secret key for HMAC verification
        max_age_seconds: Maximum age of token in seconds
        require_user_data: Whether user data is required in the token

    Returns:
        True if token is valid and not expired

    Examples:
        >>> token = generate_csrf_token("sess-abc123", "secret-key")
        >>> is_valid = validate_csrf_token(token, "sess-abc123", "secret-key")
        >>> print(is_valid)
        True
    """
    try:
        info = extract_csrf_token_info(token, session_id, secret_key)

        if not info.is_valid:
            return False

        # Check expiration
        if info.is_expired_for_max_age(max_age_seconds):
            return False

        # Check user data requirement
        if require_user_data and not info.user_data:
            return False

        return True

    except Exception:
        return False


def extract_csrf_token_info(
    token: str,
    session_id: str,
    secret_key: str,
) -> CSRFTokenInfo:
    """
    Extract information from a CSRF token without validating it.

    This function parses the token and extracts metadata but still validates
    the signature to ensure the token hasn't been tampered with.

    Args:
        token: CSRF token to parse
        session_id: Expected session ID
        secret_key: Server secret key for signature verification

    Returns:
        CSRFTokenInfo object with token details

    Examples:
        >>> token = generate_csrf_token("sess-abc123", "secret", user_data={"action": "delete"})
        >>> info = extract_csrf_token_info(token, "sess-abc123", "secret")
        >>> print(info.user_data)
        {'action': 'delete'}
        >>> print(info.age_seconds)
        5
    """
    try:
        # Parse token format: timestamp:user_data_b64:signature
        parts = token.split(":", 2)
        if len(parts) != 3:
            return CSRFTokenInfo(
                session_id="",
                timestamp=0,
                token_type=TokenType.HMAC,
                is_valid=False,
                error="Invalid token format",
            )

        timestamp_str, user_data_b64, signature = parts

        # Parse timestamp
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return CSRFTokenInfo(
                session_id="",
                timestamp=0,
                token_type=TokenType.HMAC,
                is_valid=False,
                error="Invalid timestamp",
            )

        # Decode user data
        user_data = {}
        if user_data_b64:
            try:
                # Add padding for decoding, but keep original for message signing
                padded_b64 = user_data_b64
                padding = 4 - (len(padded_b64) % 4)
                if padding != 4:
                    padded_b64 += "=" * padding

                user_data_json = base64.urlsafe_b64decode(padded_b64).decode("utf-8")
                user_data = json.loads(user_data_json)
            except (ValueError, json.JSONDecodeError):
                return CSRFTokenInfo(
                    session_id=session_id,
                    timestamp=timestamp,
                    token_type=TokenType.HMAC,
                    is_valid=False,
                    error="Invalid user data encoding",
                )

        # Verify signature
        message = f"{session_id}:{timestamp}:{user_data_b64}"
        expected_signature = hmac.new(
            secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature, expected_signature):
            return CSRFTokenInfo(
                session_id=session_id,
                timestamp=timestamp,
                token_type=TokenType.HMAC,
                user_data=user_data,
                is_valid=False,
                error="Invalid signature",
            )

        return CSRFTokenInfo(
            session_id=session_id,
            timestamp=timestamp,
            token_type=TokenType.HMAC,
            user_data=user_data,
            is_valid=True,
        )

    except Exception as e:
        return CSRFTokenInfo(
            session_id="",
            timestamp=0,
            token_type=TokenType.HMAC,
            is_valid=False,
            error=f"Token parsing error: {str(e)}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Double Submit Cookie CSRF Tokens
# ─────────────────────────────────────────────────────────────────────────────


def generate_double_submit_token(
    session_id: str,
    secret_key: str,
    cookie_value: Optional[str] = None,
) -> tuple[str, str]:
    """
    Generate a double submit cookie CSRF token pair.

    This method generates two tokens:
    1. A cookie token (stored in HTTP-only cookie)
    2. A form token (included in forms/headers)

    Both tokens must match to validate the request, preventing CSRF attacks
    even when the attacker can't access the cookie value.

    Args:
        session_id: Session ID to bind tokens to
        secret_key: Server secret key for token generation
        cookie_value: Optional specific value for cookie (auto-generated if None)

    Returns:
        Tuple of (cookie_token, form_token)

    Examples:
        >>> cookie_token, form_token = generate_double_submit_token("sess-abc123", "secret")
        >>> print(f"Cookie: {cookie_token}")
        Cookie: eyJzaWQiOiJzZXNzLWFiYzEyMyIsInRzIjoxNzAzMTIzNDU2fQ.a1b2c3...
        >>> print(f"Form: {form_token}")
        Form: a1b2c3d4e5f6789012345678901234567890abcdef...
    """
    timestamp = int(time.time())

    # Generate random cookie value if not provided
    if cookie_value is None:
        cookie_value = secrets.token_urlsafe(32)

    # Create cookie token with session binding
    cookie_data = {"sid": session_id, "ts": timestamp, "val": cookie_value}

    cookie_json = json.dumps(cookie_data, separators=(",", ":"))
    cookie_b64 = (
        base64.urlsafe_b64encode(cookie_json.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )

    # Sign the cookie token
    cookie_signature = hmac.new(
        secret_key.encode("utf-8"), cookie_b64.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]  # Truncate for space efficiency

    cookie_token = f"{cookie_b64}.{cookie_signature}"

    # Create form token by hashing cookie value with session
    form_token = hmac.new(
        secret_key.encode("utf-8"),
        f"{session_id}:{cookie_value}:{timestamp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return cookie_token, form_token


def validate_double_submit_token(
    cookie_token: str,
    form_token: str,
    session_id: str,
    secret_key: str,
    max_age_seconds: int = DEFAULT_CSRF_TOKEN_MAX_AGE,
) -> bool:
    """
    Validate a double submit cookie CSRF token pair.

    Args:
        cookie_token: Token from the cookie
        form_token: Token from the form/header
        session_id: Expected session ID
        secret_key: Server secret key
        max_age_seconds: Maximum age of tokens

    Returns:
        True if both tokens are valid and match

    Examples:
        >>> cookie_token, form_token = generate_double_submit_token("sess-abc123", "secret")
        >>> is_valid = validate_double_submit_token(cookie_token, form_token, "sess-abc123", "secret")
        >>> print(is_valid)
        True
    """
    try:
        # Parse and validate cookie token
        if "." not in cookie_token:
            return False

        cookie_b64, cookie_signature = cookie_token.rsplit(".", 1)

        # Verify cookie signature
        expected_cookie_signature = hmac.new(
            secret_key.encode("utf-8"), cookie_b64.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]

        if not hmac.compare_digest(cookie_signature, expected_cookie_signature):
            return False

        # Decode cookie data
        padding = 4 - (len(cookie_b64) % 4)
        if padding != 4:
            cookie_b64 += "=" * padding

        cookie_json = base64.urlsafe_b64decode(cookie_b64).decode("utf-8")
        cookie_data = json.loads(cookie_json)

        # Validate cookie data structure
        if not all(key in cookie_data for key in ["sid", "ts", "val"]):
            return False

        # Check session ID match
        if cookie_data["sid"] != session_id:
            return False

        # Check token age
        token_age = int(time.time()) - cookie_data["ts"]
        if token_age > max_age_seconds:
            return False

        # Generate expected form token
        expected_form_token = hmac.new(
            secret_key.encode("utf-8"),
            f"{session_id}:{cookie_data['val']}:{cookie_data['ts']}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Validate form token
        return hmac.compare_digest(form_token, expected_form_token)

    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Encrypted CSRF Tokens (for stateless operation)
# ─────────────────────────────────────────────────────────────────────────────


def generate_encrypted_csrf_token(
    session_id: str,
    secret_key: str,
    user_data: Optional[dict[str, Any]] = None,
    timestamp: Optional[int] = None,
) -> str:
    """
    Generate an encrypted CSRF token for stateless operation.

    This creates a self-contained token that includes all necessary information
    encrypted with the secret key. No server-side storage is required.

    Args:
        session_id: Session ID to bind token to
        secret_key: Server secret key for encryption
        user_data: Optional additional data to encrypt in token
        timestamp: Unix timestamp (defaults to current time)

    Returns:
        Encrypted CSRF token string

    Note:
        This is a simplified encryption using HMAC-based approach.
        For production use with highly sensitive data, consider using
        proper authenticated encryption like AES-GCM.

    Examples:
        >>> token = generate_encrypted_csrf_token(
        ...     "sess-abc123",
        ...     "secret-key",
        ...     user_data={"action": "transfer", "amount": 1000}
        ... )
    """
    if timestamp is None:
        timestamp = int(time.time())

    # Create token payload
    payload = {"sid": session_id, "ts": timestamp, "data": user_data or {}}

    # Serialize and encrypt payload
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    # Generate encryption key from secret
    encryption_key = hashlib.pbkdf2_hmac(
        "sha256",
        secret_key.encode("utf-8"),
        b"csrf_token_salt",
        100000,  # iterations
        32,  # key length
    )

    # Simple encryption using XOR with key stream (for demo purposes)
    # In production, use proper authenticated encryption
    payload_bytes = payload_json.encode("utf-8")

    # Generate key stream
    key_stream = []
    for i in range(len(payload_bytes)):
        key_stream.append(encryption_key[i % len(encryption_key)])

    # XOR encrypt
    encrypted_bytes = bytes(a ^ b for a, b in zip(payload_bytes, key_stream))

    # Base64 encode
    encrypted_b64 = (
        base64.urlsafe_b64encode(encrypted_bytes).decode("ascii").rstrip("=")
    )

    # Generate authentication tag
    auth_tag = hmac.new(
        secret_key.encode("utf-8"),
        f"encrypted_csrf:{encrypted_b64}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]  # Truncate for efficiency

    return f"enc:{encrypted_b64}:{auth_tag}"


def validate_encrypted_csrf_token(
    token: str,
    session_id: str,
    secret_key: str,
    max_age_seconds: int = DEFAULT_CSRF_TOKEN_MAX_AGE,
) -> tuple[bool, Optional[dict[str, Any]]]:
    """
    Validate an encrypted CSRF token and return decrypted user data.

    Args:
        token: Encrypted CSRF token
        session_id: Expected session ID
        secret_key: Server secret key for decryption
        max_age_seconds: Maximum age of token

    Returns:
        Tuple of (is_valid, user_data)

    Examples:
        >>> token = generate_encrypted_csrf_token("sess-abc123", "secret", {"action": "delete"})
        >>> is_valid, user_data = validate_encrypted_csrf_token(token, "sess-abc123", "secret")
        >>> print(is_valid, user_data)
        True {'action': 'delete'}
    """
    try:
        # Parse token format: enc:encrypted_b64:auth_tag
        if not token.startswith("enc:"):
            return False, None

        parts = token[4:].split(":", 1)
        if len(parts) != 2:
            return False, None

        encrypted_b64, auth_tag = parts

        # Verify authentication tag
        expected_auth_tag = hmac.new(
            secret_key.encode("utf-8"),
            f"encrypted_csrf:{encrypted_b64}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]

        if not hmac.compare_digest(auth_tag, expected_auth_tag):
            return False, None

        # Decrypt payload
        encryption_key = hashlib.pbkdf2_hmac(
            "sha256", secret_key.encode("utf-8"), b"csrf_token_salt", 100000, 32
        )

        # Add padding if needed
        padding = 4 - (len(encrypted_b64) % 4)
        if padding != 4:
            encrypted_b64 += "=" * padding

        encrypted_bytes = base64.urlsafe_b64decode(encrypted_b64)

        # Generate key stream and decrypt
        key_stream = []
        for i in range(len(encrypted_bytes)):
            key_stream.append(encryption_key[i % len(encryption_key)])

        decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, key_stream))
        payload_json = decrypted_bytes.decode("utf-8")

        # Parse payload
        payload = json.loads(payload_json)

        # Validate payload structure
        if not all(key in payload for key in ["sid", "ts"]):
            return False, None

        # Check session ID
        if payload["sid"] != session_id:
            return False, None

        # Check token age
        token_age = int(time.time()) - payload["ts"]
        if token_age > max_age_seconds:
            return False, None

        return True, payload.get("data", {})

    except Exception:
        return False, None


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────


def is_csrf_token_expired(
    token: str,
    session_id: str,
    secret_key: str,
    max_age_seconds: int = DEFAULT_CSRF_TOKEN_MAX_AGE,
) -> bool:
    """
    Check if a CSRF token is expired without full validation.

    This is useful for providing specific "token expired" error messages
    vs generic "invalid token" messages.

    Args:
        token: CSRF token to check
        session_id: Session ID for token parsing
        secret_key: Secret key for token parsing
        max_age_seconds: Maximum age threshold

    Returns:
        True if token is expired (but otherwise valid)

    Examples:
        >>> # Generate token and wait
        >>> token = generate_csrf_token("sess-abc123", "secret")
        >>> time.sleep(3601)  # Wait over 1 hour
        >>> is_expired = is_csrf_token_expired(token, "sess-abc123", "secret", 3600)
        >>> print(is_expired)
        True
    """
    try:
        info = extract_csrf_token_info(token, session_id, secret_key)
        return info.is_valid and info.is_expired_for_max_age(max_age_seconds)
    except Exception:
        return False


def _constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.

    This is a wrapper around hmac.compare_digest for consistency.
    """
    return hmac.compare_digest(a, b)


def _validate_csrf_token_format(token: str) -> bool:
    """
    Validate basic CSRF token format without cryptographic verification.

    Args:
        token: Token to validate format

    Returns:
        True if token has valid format
    """
    if not token or not isinstance(token, str):
        return False

    # Check for encrypted format first since it's most specific
    if token.startswith("enc:"):
        enc_parts = token.split(":")
        if len(enc_parts) == 3:  # Should have exactly enc, data, tag
            return True

    # Check for basic HMAC token format: timestamp:user_data:signature
    parts = token.split(":")
    if len(parts) == 3:
        timestamp_str, user_data_b64, signature = parts
        # Check timestamp is numeric
        try:
            int(timestamp_str)
        except ValueError:
            pass  # Not HMAC format, try other formats
        else:
            # Check signature is hex
            if len(signature) == 64 and all(c in "0123456789abcdef" for c in signature):
                return True

    # Check for double submit format: data.signature
    if "." in token:
        dot_parts = token.split(".")
        if len(dot_parts) == 2:
            return True

    return False
