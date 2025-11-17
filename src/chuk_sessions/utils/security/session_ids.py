# -*- coding: utf-8 -*-
# chuk_sessions/utils/security/session_ids.py
"""
Secure session ID generation and validation.

This module provides cryptographically secure session ID generation and validation
for various protocols including MCP, HTTP, WebSocket, and custom formats. All
session IDs are generated using the system's cryptographically secure random
number generator and follow protocol-specific requirements.
"""

from __future__ import annotations

import math
import re
import secrets
import time
import uuid
from typing import Any, Optional

from ...enums import ProtocolType
from .constants import (
    COMPATIBILITY,
    DEFAULT_MIN_ENTROPY_BITS,
    DEFAULT_SESSION_ID_MIN_LENGTH,
    ERROR_MESSAGES,
    MIN_CHARACTER_TYPES,
    MIN_UNIQUE_CHARACTERS,
    PATTERNS,
    SESSION_ID_FORMATS,
)

__all__ = [
    "generate_secure_session_id",
    "validate_session_id_format",
    "estimate_entropy",
    "analyze_session_id_strength",
]


# ─────────────────────────────────────────────────────────────────────────────
# Session ID Generation
# ─────────────────────────────────────────────────────────────────────────────


def generate_secure_session_id(
    protocol: str | ProtocolType = ProtocolType.GENERIC,
    custom_format: Optional[dict[str, Any]] = None,
    include_timestamp: bool = False,
    entropy_bits: Optional[int] = None,
) -> str:
    """
    Generate a cryptographically secure session ID.

    Uses the system's cryptographically secure random number generator
    and follows best practices for session ID generation including
    sufficient entropy and protocol-specific format requirements.

    Args:
        protocol: Protocol type (ProtocolType enum or string)
        custom_format: Override default format with {length, alphabet, prefix, separator}
        include_timestamp: Include timestamp component for debugging/tracing
        entropy_bits: Minimum entropy requirement (overrides default)

    Returns:
        Cryptographically secure session ID

    Raises:
        ValueError: If protocol is unknown or custom format is invalid

    Examples:
        >>> generate_secure_session_id(ProtocolType.MCP)
        'mcp-a1b2c3d4-e5f6-7890-abcd-ef1234567890'

        >>> generate_secure_session_id(ProtocolType.HTTP)
        'http-X9zK2mN8qP4vR7sT5wY1uC3eI6oL9rE2'

        >>> generate_secure_session_id(ProtocolType.UUID)
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'

        >>> generate_secure_session_id("custom", {"length": 20, "alphabet": "ABCDEF0123456789", "prefix": "test"})
        'test-A1B2C3D4E5F67890ABCD'
    """
    # Convert string protocol to enum if needed
    if isinstance(protocol, str):
        try:
            protocol = ProtocolType(protocol)
        except ValueError:
            # Not a standard protocol, will be handled below
            pass

    # Handle special cases first
    if protocol == ProtocolType.UUID or protocol == "uuid":
        return str(uuid.uuid4())

    if protocol == ProtocolType.JWT or protocol == "jwt":
        # For JWT, we generate a random jti (JWT ID) claim
        # Use sufficient entropy for JWT tokens
        length = _calculate_required_length(
            entropy_bits or 128, 64
        )  # Base64 alphabet size
        return secrets.token_urlsafe(length)

    # Get the protocol value for lookups
    protocol_str = protocol.value if isinstance(protocol, ProtocolType) else protocol

    # Get format configuration
    if custom_format:
        format_config = custom_format.copy()
        _validate_custom_format(format_config)
    elif protocol_str in SESSION_ID_FORMATS:
        format_config = SESSION_ID_FORMATS[protocol_str].copy()
    else:
        raise ValueError(
            f"Unknown protocol '{protocol_str}'. "
            f"Available protocols: {', '.join(SESSION_ID_FORMATS.keys())} "
            f"or provide custom_format."
        )

    # Extract format parameters with defaults
    length = format_config.get("length", 32)
    alphabet = format_config.get("alphabet", "")
    prefix = format_config.get("prefix", "")
    separator = format_config.get("separator", "-")

    # Validate entropy requirements
    required_entropy = entropy_bits or DEFAULT_MIN_ENTROPY_BITS
    if not _validate_entropy_requirement(length, alphabet, required_entropy):
        # Adjust length to meet entropy requirements
        length = _calculate_required_length(required_entropy, len(alphabet))
        if length > 100:  # Sanity check
            raise ValueError(
                f"Cannot generate session ID with {required_entropy} bits of entropy "
                f"using alphabet of size {len(alphabet)}. Consider using a larger alphabet."
            )

    # Generate the random component
    random_part = _generate_random_string(length, alphabet)

    # Build session ID parts
    parts = []

    if prefix:
        parts.append(prefix)

    if include_timestamp:
        # Add timestamp for debugging (not for security)
        timestamp = hex(int(time.time()))[2:]  # Remove '0x' prefix
        parts.append(timestamp)

    parts.append(random_part)

    # Join parts with separator
    session_id = separator.join(parts) if separator else "".join(parts)

    # Validate for protocol compliance
    if protocol == "mcp":
        if not _validate_mcp_compliance(session_id):
            # Fallback to UUID if our generated ID doesn't meet MCP requirements
            return f"mcp{separator}{uuid.uuid4()}"

    return session_id


def _generate_random_string(length: int, alphabet: str) -> str:
    """Generate a cryptographically secure random string."""
    if not alphabet:
        raise ValueError("Alphabet cannot be empty")

    return "".join(secrets.choice(alphabet) for _ in range(length))


def _calculate_required_length(entropy_bits: int, alphabet_size: int) -> int:
    """Calculate the required length to achieve target entropy."""
    if alphabet_size <= 1:
        raise ValueError("Alphabet size must be greater than 1")

    # Entropy = length * log2(alphabet_size)
    # length = entropy / log2(alphabet_size)
    bits_per_char = math.log2(alphabet_size)
    required_length = math.ceil(entropy_bits / bits_per_char)

    # Ensure minimum length
    return max(required_length, DEFAULT_SESSION_ID_MIN_LENGTH)


def _validate_custom_format(format_config: dict[str, Any]) -> None:
    """Validate custom format configuration."""
    length = format_config.get("length", 0)
    alphabet = format_config.get("alphabet", "")

    if length < DEFAULT_SESSION_ID_MIN_LENGTH:
        raise ValueError(
            ERROR_MESSAGES["session_id_too_short"].format(
                min_length=DEFAULT_SESSION_ID_MIN_LENGTH
            )
        )

    if len(alphabet) < 2:
        raise ValueError("Alphabet must contain at least 2 characters for entropy")

    # Check for duplicate characters in alphabet
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("Alphabet cannot contain duplicate characters")


def _validate_entropy_requirement(
    length: int, alphabet: str, required_bits: int
) -> bool:
    """Check if the given length and alphabet provide sufficient entropy."""
    if not alphabet:
        return False

    alphabet_size = len(set(alphabet))  # Unique characters only
    actual_entropy = length * math.log2(alphabet_size)

    return actual_entropy >= required_bits


def _validate_mcp_compliance(session_id: str) -> bool:
    """Validate MCP protocol compliance."""
    # Check visible ASCII requirement (0x21 to 0x7E)
    if not all(0x21 <= ord(c) <= 0x7E for c in session_id):
        return False

    # Check against known MCP patterns
    return bool(
        PATTERNS["mcp_uuid"].match(session_id)
        or PATTERNS["mcp_custom"].match(session_id)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Session ID Validation
# ─────────────────────────────────────────────────────────────────────────────


def validate_session_id_format(
    session_id: str,
    protocol: str = "generic",
    min_entropy_bits: Optional[int] = None,
    strict_mode: bool = True,
) -> bool:
    """
    Validate session ID format and security properties.

    Checks that session IDs meet security requirements including
    sufficient length, character set restrictions, and entropy estimates.

    Args:
        session_id: Session ID to validate
        protocol: Expected protocol (affects character set validation)
        min_entropy_bits: Minimum entropy requirement in bits
        strict_mode: Whether to apply strict validation rules

    Returns:
        True if session ID format is valid and secure

    Examples:
        >>> validate_session_id_format("mcp-a1b2c3d4-e5f6-7890-abcd-ef1234567890", "mcp")
        True

        >>> validate_session_id_format("weak123", "generic")
        False

        >>> validate_session_id_format("custom-session", "generic", min_entropy_bits=64, strict_mode=False)
        True
    """
    if not session_id or not isinstance(session_id, str):
        return False

    # Basic length check
    min_length = DEFAULT_SESSION_ID_MIN_LENGTH
    if len(session_id) < min_length:
        return False

    # Protocol-specific validation
    if not _validate_protocol_specific(session_id, protocol, strict_mode):
        return False

    # UUID and JWT protocols have fixed formats with known security properties,
    # so skip entropy/diversity checks
    if protocol in ("uuid", "jwt"):
        return True

    # Entropy validation
    min_entropy = min_entropy_bits or DEFAULT_MIN_ENTROPY_BITS
    if not _validate_entropy(session_id, min_entropy, strict_mode):
        return False

    # Character diversity check
    if strict_mode and not _validate_character_diversity(session_id):
        return False

    return True


def _validate_protocol_specific(
    session_id: str, protocol: str, strict_mode: bool
) -> bool:
    """Validate protocol-specific requirements."""
    if protocol == "mcp":
        # MCP spec: only visible ASCII characters (0x21 to 0x7E)
        if not all(0x21 <= ord(c) <= 0x7E for c in session_id):
            return False

        if strict_mode:
            # Strict MCP compliance requires specific patterns
            return bool(
                PATTERNS["mcp_uuid"].match(session_id)
                or PATTERNS["mcp_custom"].match(session_id)
            )
        else:
            # Relaxed mode just checks visible ASCII
            return bool(PATTERNS["visible_ascii"].match(session_id))

    elif protocol == "http":
        # HTTP sessions: URL-safe characters
        if strict_mode:
            return bool(PATTERNS["http_session"].match(session_id))
        else:
            return bool(
                PATTERNS["http_session_relaxed"].match(session_id.split("-", 1)[-1])
            )

    elif protocol == "websocket":
        # WebSocket: similar to HTTP
        return bool(PATTERNS["websocket_session"].match(session_id))

    elif protocol == "uuid":
        # UUID format validation
        return bool(PATTERNS["uuid_any"].match(session_id))

    elif protocol == "jwt":
        # JWT tokens should be URL-safe base64
        return bool(PATTERNS["base64_urlsafe"].match(session_id))

    elif protocol == "generic":
        # Generic validation - allow alphanumeric and common separators
        return bool(re.match(r"^[a-zA-Z0-9_-]+$", session_id))

    # Unknown protocol - apply generic validation
    return bool(re.match(r"^[a-zA-Z0-9_.-]+$", session_id))


def _validate_entropy(
    session_id: str, min_entropy_bits: int, strict_mode: bool
) -> bool:
    """Validate entropy requirements."""
    if COMPATIBILITY.get("allow_weak_entropy_in_tests", False) and not strict_mode:
        return True

    estimated_entropy = estimate_entropy(session_id)
    return estimated_entropy >= min_entropy_bits


def _validate_character_diversity(session_id: str) -> bool:
    """Validate character diversity to prevent weak session IDs."""
    # Check unique character count
    unique_chars = len(set(session_id))
    if unique_chars < MIN_UNIQUE_CHARACTERS:
        return False

    # Check character type diversity
    has_upper = any(c.isupper() for c in session_id)
    has_lower = any(c.islower() for c in session_id)
    has_digit = any(c.isdigit() for c in session_id)
    has_special = any(not c.isalnum() for c in session_id)

    char_types = sum([has_upper, has_lower, has_digit, has_special])
    return char_types >= MIN_CHARACTER_TYPES


# ─────────────────────────────────────────────────────────────────────────────
# Entropy Analysis
# ─────────────────────────────────────────────────────────────────────────────


def estimate_entropy(session_id: str) -> float:
    """
    Estimate the entropy of a session ID.

    This provides a conservative estimate based on character set analysis
    and pattern detection. Real entropy may be higher for truly random strings.

    Args:
        session_id: Session ID to analyze

    Returns:
        Estimated entropy in bits

    Examples:
        >>> estimate_entropy("abc123def456")
        48.7  # Example value

        >>> estimate_entropy("mcp-f47ac10b-58cc-4372-a567-0e02b2c3d479")
        122.0  # UUID has high entropy
    """
    if not session_id:
        return 0.0

    # Remove common prefixes and separators for entropy calculation
    clean_id = re.sub(r"^[a-z]+-", "", session_id)  # Remove protocol prefix
    clean_id = re.sub(r"[-_.]", "", clean_id)  # Remove separators

    if not clean_id:
        return 0.0

    # Analyze character set
    charset_size = _estimate_charset_size(clean_id)

    # Calculate base entropy
    base_entropy = len(clean_id) * math.log2(charset_size)

    # Apply penalties for patterns
    pattern_penalty = _calculate_pattern_penalty(clean_id)

    # Apply diversity bonus
    diversity_bonus = _calculate_diversity_bonus(clean_id)

    # Final entropy estimate
    estimated_entropy = base_entropy * (1 - pattern_penalty) + diversity_bonus

    return max(0.0, estimated_entropy)


def _estimate_charset_size(text: str) -> int:
    """Estimate the character set size used in the text."""
    unique_chars = set(text.lower())  # Case-insensitive analysis

    # Determine character set based on characters present
    has_letters = any(c.isalpha() for c in unique_chars)
    has_digits = any(c.isdigit() for c in unique_chars)
    has_special = any(not c.isalnum() for c in unique_chars)

    if has_letters and has_digits and has_special:
        return 94  # Full ASCII printable set
    elif has_letters and has_digits:
        return 62  # Alphanumeric
    elif has_letters:
        return 26  # Letters only
    elif has_digits:
        return 10  # Digits only
    else:
        return len(unique_chars)  # Special characters only


def _calculate_pattern_penalty(text: str) -> float:
    """Calculate penalty for detected patterns (reduces entropy estimate)."""
    penalty = 0.0

    # Check for repeated characters
    for i in range(len(text) - 1):
        if text[i] == text[i + 1]:
            penalty += 0.1

    # Check for sequential patterns
    if _has_sequential_pattern(text):
        penalty += 0.2

    # Check for keyboard patterns
    if _has_keyboard_pattern(text):
        penalty += 0.3

    # Cap penalty at 50%
    return min(penalty, 0.5)


def _calculate_diversity_bonus(text: str) -> float:
    """Calculate bonus for character diversity."""
    unique_chars = len(set(text))
    char_types = 0

    if any(c.isupper() for c in text):
        char_types += 1
    if any(c.islower() for c in text):
        char_types += 1
    if any(c.isdigit() for c in text):
        char_types += 1
    if any(not c.isalnum() for c in text):
        char_types += 1

    # Bonus for high diversity
    diversity_ratio = unique_chars / len(text)
    type_bonus = char_types * 2

    return diversity_ratio * type_bonus


def _has_sequential_pattern(text: str) -> bool:
    """Check for sequential character patterns."""
    for i in range(len(text) - 2):
        # Check ascending sequence
        if (
            ord(text[i + 1]) == ord(text[i]) + 1
            and ord(text[i + 2]) == ord(text[i + 1]) + 1
        ):
            return True
        # Check descending sequence
        if (
            ord(text[i + 1]) == ord(text[i]) - 1
            and ord(text[i + 2]) == ord(text[i + 1]) - 1
        ):
            return True
    return False


def _has_keyboard_pattern(text: str) -> bool:
    """Check for common keyboard patterns."""
    keyboard_patterns = [
        "qwerty",
        "asdf",
        "zxcv",
        "123456",
        "abcdef",
        "qwertz",
        "azerty",  # International layouts
    ]

    text_lower = text.lower()
    for pattern in keyboard_patterns:
        if pattern in text_lower:
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Session ID Analysis
# ─────────────────────────────────────────────────────────────────────────────


def analyze_session_id_strength(session_id: str) -> dict[str, Any]:
    """
    Comprehensive analysis of session ID strength.

    Provides detailed information about the security properties of a session ID
    including entropy, character diversity, patterns, and recommendations.

    Args:
        session_id: Session ID to analyze

    Returns:
        Dictionary containing analysis results

    Examples:
        >>> analyze_session_id_strength("mcp-f47ac10b-58cc-4372-a567-0e02b2c3d479")
        {
            'length': 41,
            'entropy_bits': 122.0,
            'strength': 'strong',
            'character_diversity': 0.73,
            'patterns_detected': [],
            'protocol_compliance': {'mcp': True},
            'recommendations': []
        }
    """
    if not session_id or not isinstance(session_id, str):
        return {"valid": False, "error": "Invalid session ID format"}

    # Basic properties
    length = len(session_id)
    entropy = estimate_entropy(session_id)
    unique_chars = len(set(session_id))
    diversity = unique_chars / length if length > 0 else 0

    # Detect patterns
    patterns = []
    if _has_sequential_pattern(session_id):
        patterns.append("sequential_characters")
    if _has_keyboard_pattern(session_id):
        patterns.append("keyboard_pattern")
    if len(set(session_id)) < MIN_UNIQUE_CHARACTERS:
        patterns.append("low_character_diversity")

    # Determine strength
    if entropy >= 128:
        strength = "strong"
    elif entropy >= 80:
        strength = "moderate"
    elif entropy >= 40:
        strength = "weak"
    else:
        strength = "very_weak"

    # Protocol compliance
    compliance = {}
    for protocol in ["mcp", "http", "websocket", "uuid"]:
        compliance[protocol] = validate_session_id_format(
            session_id, protocol, strict_mode=False
        )

    # Generate recommendations
    recommendations = []
    if entropy < DEFAULT_MIN_ENTROPY_BITS:
        recommendations.append(
            f"Increase entropy to at least {DEFAULT_MIN_ENTROPY_BITS} bits"
        )
    if diversity < 0.3:
        recommendations.append("Improve character diversity")
    if length < 20:
        recommendations.append("Consider longer session ID (20+ characters)")
    if patterns:
        recommendations.append("Avoid predictable patterns")

    return {
        "valid": True,
        "length": length,
        "entropy_bits": round(entropy, 1),
        "strength": strength,
        "character_diversity": round(diversity, 2),
        "unique_characters": unique_chars,
        "patterns_detected": patterns,
        "protocol_compliance": compliance,
        "recommendations": recommendations,
        "charset_estimate": _estimate_charset_size(session_id),
    }
