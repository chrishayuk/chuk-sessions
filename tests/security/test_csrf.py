# -*- coding: utf-8 -*-
"""
Test suite for chuk_sessions.utils.security.csrf module.

Comprehensive tests for CSRF token generation, validation, and security
including basic HMAC tokens, double submit cookies, encrypted tokens,
and security properties like timing attack resistance.
"""

import pytest
import time
import json
import base64
from unittest.mock import patch

from chuk_sessions.utils.security.csrf import (
    generate_csrf_token,
    validate_csrf_token,
    generate_double_submit_token,
    validate_double_submit_token,
    generate_encrypted_csrf_token,
    validate_encrypted_csrf_token,
    extract_csrf_token_info,
    is_csrf_token_expired,
    CSRFTokenInfo,
    _constant_time_compare,
    _validate_csrf_token_format,
)


class TestCSRFTokenInfo:
    """Test CSRFTokenInfo class functionality."""

    def test_csrf_token_info_creation(self):
        """Test CSRFTokenInfo object creation and properties."""
        current_time = int(time.time())
        info = CSRFTokenInfo(
            session_id="sess-abc123",
            timestamp=current_time - 60,  # 1 minute ago
            token_type="hmac",
            user_data={"action": "delete"},
            is_valid=True,
        )

        assert info.session_id == "sess-abc123"
        assert info.timestamp == current_time - 60
        assert info.token_type == "hmac"
        assert info.user_data == {"action": "delete"}
        assert info.is_valid is True
        assert info.error is None

        # Test age calculation
        assert 59 <= info.age_seconds <= 61  # Allow 1 second tolerance

    def test_csrf_token_info_expiration(self):
        """Test token expiration checking."""
        # Create expired token (2 hours ago)
        expired_time = int(time.time()) - 7200
        expired_info = CSRFTokenInfo(
            session_id="sess-abc123", timestamp=expired_time, is_valid=True
        )

        assert expired_info.is_expired is True
        assert expired_info.is_expired_for_max_age(3600) is True  # 1 hour max age
        assert expired_info.is_expired_for_max_age(10800) is False  # 3 hour max age

        # Create fresh token
        fresh_time = int(time.time()) - 60
        fresh_info = CSRFTokenInfo(
            session_id="sess-abc123", timestamp=fresh_time, is_valid=True
        )

        assert fresh_info.is_expired is False
        assert fresh_info.is_expired_for_max_age(3600) is False

    def test_csrf_token_info_to_dict(self):
        """Test dictionary conversion."""
        current_time = int(time.time())
        info = CSRFTokenInfo(
            session_id="sess-abc123",
            timestamp=current_time - 30,
            token_type="hmac",
            user_data={"action": "delete"},
            is_valid=True,
            error=None,
        )

        data = info.to_dict()

        expected_keys = {
            "session_id",
            "timestamp",
            "token_type",
            "user_data",
            "age_seconds",
            "is_valid",
            "is_expired",
            "error",
        }
        assert set(data.keys()) == expected_keys

        assert data["session_id"] == "sess-abc123"
        assert data["token_type"] == "hmac"
        assert data["user_data"] == {"action": "delete"}
        assert data["is_valid"] is True


class TestBasicCSRFTokens:
    """Test basic HMAC-based CSRF token functionality."""

    def test_generate_basic_csrf_token(self):
        """Test basic CSRF token generation."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        token = generate_csrf_token(session_id, secret_key)

        # Should be non-empty string
        assert isinstance(token, str)
        assert len(token) > 0

        # Should have timestamp:user_data:signature format
        parts = token.split(":")
        assert len(parts) == 3

        # Timestamp should be numeric
        timestamp = int(parts[0])
        assert timestamp > 0

        # Signature should be hex
        signature = parts[2]
        assert len(signature) == 64  # SHA256 hex digest
        assert all(c in "0123456789abcdef" for c in signature)

    def test_generate_csrf_token_with_timestamp(self):
        """Test CSRF token generation with custom timestamp."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        custom_timestamp = 1234567890

        token = generate_csrf_token(session_id, secret_key, custom_timestamp)

        parts = token.split(":")
        assert int(parts[0]) == custom_timestamp

    def test_generate_csrf_token_with_user_data(self):
        """Test CSRF token generation with user data."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        user_data = {"action": "delete", "resource_id": "123"}

        token = generate_csrf_token(session_id, secret_key, user_data=user_data)

        parts = token.split(":")
        assert len(parts) == 3

        # User data should be base64 encoded
        user_data_b64 = parts[1]
        assert len(user_data_b64) > 0

        # Should be able to decode user data
        padding = 4 - (len(user_data_b64) % 4)
        if padding != 4:
            user_data_b64 += "=" * padding

        decoded_json = base64.urlsafe_b64decode(user_data_b64).decode("utf-8")
        decoded_data = json.loads(decoded_json)
        assert decoded_data == user_data

    def test_generate_csrf_token_validation_errors(self):
        """Test CSRF token generation validation."""
        # Empty session ID
        with pytest.raises(ValueError, match="session_id cannot be empty"):
            generate_csrf_token("", "secret-key")

        # Empty secret key
        with pytest.raises(ValueError, match="secret_key cannot be empty"):
            generate_csrf_token("sess-abc123", "")

    def test_validate_csrf_token_success(self):
        """Test successful CSRF token validation."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        token = generate_csrf_token(session_id, secret_key)

        # Should validate successfully
        assert validate_csrf_token(token, session_id, secret_key) is True

    def test_validate_csrf_token_with_user_data(self):
        """Test CSRF token validation with user data."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        user_data = {"action": "delete", "resource_id": "123"}

        token = generate_csrf_token(session_id, secret_key, user_data=user_data)

        # Should validate successfully
        assert validate_csrf_token(token, session_id, secret_key) is True

        # Should validate with user data requirement
        assert (
            validate_csrf_token(token, session_id, secret_key, require_user_data=True)
            is True
        )

        # Token without user data should fail user data requirement
        token_no_data = generate_csrf_token(session_id, secret_key)
        assert (
            validate_csrf_token(
                token_no_data, session_id, secret_key, require_user_data=True
            )
            is False
        )

    def test_validate_csrf_token_wrong_session(self):
        """Test CSRF token validation with wrong session ID."""
        session_id = "sess-abc123"
        wrong_session = "sess-wrong456"
        secret_key = "test-secret-key"

        token = generate_csrf_token(session_id, secret_key)

        # Should fail with wrong session ID
        assert validate_csrf_token(token, wrong_session, secret_key) is False

    def test_validate_csrf_token_wrong_secret(self):
        """Test CSRF token validation with wrong secret."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        wrong_secret = "wrong-secret-key"

        token = generate_csrf_token(session_id, secret_key)

        # Should fail with wrong secret
        assert validate_csrf_token(token, session_id, wrong_secret) is False

    def test_validate_csrf_token_expiration(self):
        """Test CSRF token expiration."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        old_timestamp = int(time.time()) - 7200  # 2 hours ago

        token = generate_csrf_token(session_id, secret_key, old_timestamp)

        # Should fail due to expiration (default 1 hour)
        assert validate_csrf_token(token, session_id, secret_key) is False

        # Should pass with longer max age
        assert (
            validate_csrf_token(token, session_id, secret_key, max_age_seconds=10800)
            is True
        )

    def test_validate_csrf_token_malformed(self):
        """Test validation of malformed CSRF tokens."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Missing colons
        assert validate_csrf_token("malformed", session_id, secret_key) is False

        # Invalid timestamp
        assert (
            validate_csrf_token("notanumber::signature", session_id, secret_key)
            is False
        )

        # Empty token
        assert validate_csrf_token("", session_id, secret_key) is False

        # Wrong number of parts
        assert validate_csrf_token("one:two", session_id, secret_key) is False


class TestCSRFTokenExtraction:
    """Test CSRF token information extraction."""

    def test_extract_csrf_token_info_success(self):
        """Test successful token info extraction."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        user_data = {"action": "delete", "resource_id": "123"}
        custom_timestamp = int(time.time()) - 300  # 5 minutes ago

        token = generate_csrf_token(session_id, secret_key, custom_timestamp, user_data)
        info = extract_csrf_token_info(token, session_id, secret_key)

        assert info.is_valid is True
        assert info.session_id == session_id
        assert info.timestamp == custom_timestamp
        assert info.token_type == "hmac"
        assert info.user_data == user_data
        assert info.error is None
        assert 299 <= info.age_seconds <= 301  # Should be about 5 minutes

    def test_extract_csrf_token_info_invalid_format(self):
        """Test token info extraction with invalid format."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        info = extract_csrf_token_info("malformed", session_id, secret_key)

        assert info.is_valid is False
        assert info.error == "Invalid token format"

    def test_extract_csrf_token_info_invalid_timestamp(self):
        """Test token info extraction with invalid timestamp."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        info = extract_csrf_token_info("notanumber::signature", session_id, secret_key)

        assert info.is_valid is False
        assert info.error == "Invalid timestamp"

    def test_extract_csrf_token_info_invalid_signature(self):
        """Test token info extraction with invalid signature."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        timestamp = int(time.time())

        # Create token with wrong signature
        malformed_token = f"{timestamp}::wrongsignature"
        info = extract_csrf_token_info(malformed_token, session_id, secret_key)

        assert info.is_valid is False
        assert (
            "Invalid signature" in info.error
        )  # Changed to check if error contains the string

    def test_extract_csrf_token_info_invalid_user_data(self):
        """Test token info extraction with invalid user data encoding."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        timestamp = int(time.time())

        # Create token with invalid base64 user data
        invalid_b64 = "invalid_base64!"
        message = f"{session_id}:{timestamp}:{invalid_b64}"

        import hmac
        import hashlib

        signature = hmac.new(
            secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        malformed_token = f"{timestamp}:{invalid_b64}:{signature}"
        info = extract_csrf_token_info(malformed_token, session_id, secret_key)

        assert info.is_valid is False
        assert "Invalid user data encoding" in info.error


class TestDoubleSubmitTokens:
    """Test double submit cookie CSRF token functionality."""

    def test_generate_double_submit_token(self):
        """Test double submit token generation."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        cookie_token, form_token = generate_double_submit_token(session_id, secret_key)

        # Both tokens should be non-empty strings
        assert isinstance(cookie_token, str) and len(cookie_token) > 0
        assert isinstance(form_token, str) and len(form_token) > 0

        # Cookie token should have format: base64.signature
        assert "." in cookie_token
        cookie_parts = cookie_token.split(".")
        assert len(cookie_parts) == 2

        # Form token should be hex digest
        assert len(form_token) == 64  # SHA256 hex digest
        assert all(c in "0123456789abcdef" for c in form_token)

    def test_generate_double_submit_token_with_custom_cookie(self):
        """Test double submit token generation with custom cookie value."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        custom_cookie_value = "my-custom-cookie-value"

        cookie_token, form_token = generate_double_submit_token(
            session_id, secret_key, custom_cookie_value
        )

        # Should generate tokens successfully
        assert len(cookie_token) > 0
        assert len(form_token) > 0

    def test_validate_double_submit_token_success(self):
        """Test successful double submit token validation."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        cookie_token, form_token = generate_double_submit_token(session_id, secret_key)

        # Should validate successfully
        assert (
            validate_double_submit_token(
                cookie_token, form_token, session_id, secret_key
            )
            is True
        )

    def test_validate_double_submit_token_wrong_session(self):
        """Test double submit token validation with wrong session."""
        session_id = "sess-abc123"
        wrong_session = "sess-wrong456"
        secret_key = "test-secret-key"

        cookie_token, form_token = generate_double_submit_token(session_id, secret_key)

        # Should fail with wrong session
        assert (
            validate_double_submit_token(
                cookie_token, form_token, wrong_session, secret_key
            )
            is False
        )

    def test_validate_double_submit_token_mismatched_tokens(self):
        """Test double submit token validation with mismatched tokens."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        cookie_token1, _ = generate_double_submit_token(session_id, secret_key)
        _, form_token2 = generate_double_submit_token(session_id, secret_key)

        # Should fail with mismatched tokens
        assert (
            validate_double_submit_token(
                cookie_token1, form_token2, session_id, secret_key
            )
            is False
        )

    def test_validate_double_submit_token_expired(self):
        """Test double submit token validation with expired tokens."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Mock time to create old timestamp
        with patch("chuk_sessions.utils.security.csrf.time.time", return_value=1000):
            cookie_token, form_token = generate_double_submit_token(
                session_id, secret_key
            )

        # Reset time to current
        with patch("chuk_sessions.utils.security.csrf.time.time", return_value=8000):
            # Should fail due to expiration (7000 seconds > default 3600)
            assert (
                validate_double_submit_token(
                    cookie_token, form_token, session_id, secret_key
                )
                is False
            )

            # Should pass with longer max age
            assert (
                validate_double_submit_token(
                    cookie_token,
                    form_token,
                    session_id,
                    secret_key,
                    max_age_seconds=10000,
                )
                is True
            )

    def test_validate_double_submit_token_malformed(self):
        """Test double submit token validation with malformed tokens."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Malformed cookie token (no dot)
        assert (
            validate_double_submit_token(
                "malformed", "form_token", session_id, secret_key
            )
            is False
        )

        # Invalid cookie signature
        assert (
            validate_double_submit_token(
                "eyJ0ZXN0IjoidmFsdWUifQ.invalid", "form_token", session_id, secret_key
            )
            is False
        )


class TestEncryptedTokens:
    """Test encrypted CSRF token functionality."""

    def test_generate_encrypted_csrf_token(self):
        """Test encrypted CSRF token generation."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        user_data = {"action": "transfer", "amount": 1000}

        token = generate_encrypted_csrf_token(session_id, secret_key, user_data)

        # Should start with 'enc:' prefix
        assert token.startswith("enc:")

        # Should have format: enc:encrypted_data:auth_tag
        parts = token[4:].split(":", 1)
        assert len(parts) == 2

        encrypted_data, auth_tag = parts
        assert len(encrypted_data) > 0
        assert len(auth_tag) == 16  # Truncated auth tag

    def test_generate_encrypted_csrf_token_with_timestamp(self):
        """Test encrypted token generation with custom timestamp."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        custom_timestamp = 1234567890

        token = generate_encrypted_csrf_token(
            session_id, secret_key, timestamp=custom_timestamp
        )

        # Should generate successfully
        assert token.startswith("enc:")
        assert len(token) > 20

    def test_validate_encrypted_csrf_token_success(self):
        """Test successful encrypted CSRF token validation."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        user_data = {"action": "transfer", "amount": 1000}

        token = generate_encrypted_csrf_token(session_id, secret_key, user_data)
        is_valid, decrypted_data = validate_encrypted_csrf_token(
            token, session_id, secret_key
        )

        assert is_valid is True
        assert decrypted_data == user_data

    def test_validate_encrypted_csrf_token_no_user_data(self):
        """Test encrypted token validation without user data."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        token = generate_encrypted_csrf_token(session_id, secret_key)
        is_valid, decrypted_data = validate_encrypted_csrf_token(
            token, session_id, secret_key
        )

        assert is_valid is True
        assert decrypted_data == {}

    def test_validate_encrypted_csrf_token_wrong_session(self):
        """Test encrypted token validation with wrong session."""
        session_id = "sess-abc123"
        wrong_session = "sess-wrong456"
        secret_key = "test-secret-key"

        token = generate_encrypted_csrf_token(session_id, secret_key)
        is_valid, decrypted_data = validate_encrypted_csrf_token(
            token, wrong_session, secret_key
        )

        assert is_valid is False
        assert decrypted_data is None

    def test_validate_encrypted_csrf_token_wrong_secret(self):
        """Test encrypted token validation with wrong secret."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        wrong_secret = "wrong-secret-key"

        token = generate_encrypted_csrf_token(session_id, secret_key)
        is_valid, decrypted_data = validate_encrypted_csrf_token(
            token, session_id, wrong_secret
        )

        assert is_valid is False
        assert decrypted_data is None

    def test_validate_encrypted_csrf_token_expired(self):
        """Test encrypted token validation with expired token."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"
        old_timestamp = int(time.time()) - 7200  # 2 hours ago

        token = generate_encrypted_csrf_token(
            session_id, secret_key, timestamp=old_timestamp
        )
        is_valid, decrypted_data = validate_encrypted_csrf_token(
            token, session_id, secret_key
        )

        # Should fail due to expiration
        assert is_valid is False
        assert decrypted_data is None

        # Should pass with longer max age
        is_valid, decrypted_data = validate_encrypted_csrf_token(
            token, session_id, secret_key, max_age_seconds=10800
        )
        assert is_valid is True

    def test_validate_encrypted_csrf_token_malformed(self):
        """Test encrypted token validation with malformed tokens."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Wrong prefix
        assert validate_encrypted_csrf_token(
            "wrong:prefix", session_id, secret_key
        ) == (False, None)

        # Invalid format
        assert validate_encrypted_csrf_token(
            "enc:malformed", session_id, secret_key
        ) == (False, None)

        # Invalid auth tag
        assert validate_encrypted_csrf_token(
            "enc:data:invalid_auth_tag", session_id, secret_key
        ) == (False, None)


class TestUtilityFunctions:
    """Test utility functions."""

    def test_is_csrf_token_expired(self):
        """Test CSRF token expiration checking."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Create fresh token
        fresh_token = generate_csrf_token(session_id, secret_key)
        assert is_csrf_token_expired(fresh_token, session_id, secret_key) is False

        # Create expired token
        expired_timestamp = int(time.time()) - 7200  # 2 hours ago
        expired_token = generate_csrf_token(session_id, secret_key, expired_timestamp)
        assert is_csrf_token_expired(expired_token, session_id, secret_key) is True

        # Test with custom max age
        assert (
            is_csrf_token_expired(
                expired_token, session_id, secret_key, max_age_seconds=10800
            )
            is False
        )

    def test_is_csrf_token_expired_malformed(self):
        """Test expiration checking with malformed tokens."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Malformed token should return False (not expired, just invalid)
        assert is_csrf_token_expired("malformed", session_id, secret_key) is False

    def test_constant_time_compare(self):
        """Test constant-time comparison function."""
        # Equal strings
        assert _constant_time_compare("hello", "hello") is True

        # Different strings
        assert _constant_time_compare("hello", "world") is False

        # Different lengths
        assert _constant_time_compare("short", "longer_string") is False

        # Empty strings
        assert _constant_time_compare("", "") is True
        assert _constant_time_compare("", "test") is False

    def test_validate_csrf_token_format(self):
        """Test CSRF token format validation."""
        # Generate a real token to test the actual format
        session_id = "sess-test"
        secret_key = "test-secret"
        real_token = generate_csrf_token(session_id, secret_key)

        # The real token should validate
        assert _validate_csrf_token_format(real_token) is True

        # Valid double submit format
        assert _validate_csrf_token_format("eyJkYXRhIjoidmFsdWUifQ.signature") is True

        # Valid encrypted format - test both generated and manual formats
        encrypted_token = generate_encrypted_csrf_token(session_id, secret_key)
        print(f"Generated encrypted token: {encrypted_token}")

        # Debug step by step
        print(f"Token starts with 'enc:': {encrypted_token.startswith('enc:')}")
        parts = encrypted_token.split(":")
        print(f"Split parts: {parts}")
        print(f"Number of parts: {len(parts)}")

        # Test the validation manually
        result = _validate_csrf_token_format(encrypted_token)
        print(f"Validation result: {result}")

        assert result is True, (
            f"Encrypted token validation failed for: {encrypted_token}"
        )

        # Manual encrypted format should also work
        assert _validate_csrf_token_format("enc:encrypted_data:auth_tag") is True

        # Invalid formats
        assert _validate_csrf_token_format("") is False
        assert _validate_csrf_token_format(None) is False
        assert _validate_csrf_token_format("malformed") is False
        assert _validate_csrf_token_format("not:a:valid:timestamp:format") is False


class TestSecurityProperties:
    """Test security properties and attack resistance."""

    def test_timing_attack_resistance(self):
        """Test that validation uses constant-time operations."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Generate valid token
        valid_token = generate_csrf_token(session_id, secret_key)

        # Create invalid token with same format
        import time as time_module

        timestamp = int(time_module.time())
        invalid_signature = "0" * 64  # Wrong signature
        invalid_token = f"{timestamp}::{invalid_signature}"

        # Both validations should take similar time (hard to test precisely)
        # But we can verify they both use the same code path

        # Valid token
        start_time = time_module.perf_counter()
        result1 = validate_csrf_token(valid_token, session_id, secret_key)
        time1 = time_module.perf_counter() - start_time

        # Invalid token
        start_time = time_module.perf_counter()
        result2 = validate_csrf_token(invalid_token, session_id, secret_key)
        time2 = time_module.perf_counter() - start_time

        assert result1 is True
        assert result2 is False

        # Times should be reasonably close (within 10x of each other)
        # This is a loose test since timing can vary
        ratio = max(time1, time2) / min(time1, time2)
        assert ratio < 10.0  # Allow 10x difference for timing variations

    def test_session_binding(self):
        """Test that tokens are properly bound to sessions."""
        session1 = "sess-abc123"
        session2 = "sess-def456"
        secret_key = "test-secret-key"

        # Generate token for session1
        token = generate_csrf_token(session1, secret_key)

        # Should validate for session1
        assert validate_csrf_token(token, session1, secret_key) is True

        # Should NOT validate for session2
        assert validate_csrf_token(token, session2, secret_key) is False

    def test_secret_key_binding(self):
        """Test that tokens are properly bound to secret keys."""
        session_id = "sess-abc123"
        secret1 = "secret-key-1"
        secret2 = "secret-key-2"

        # Generate token with secret1
        token = generate_csrf_token(session_id, secret1)

        # Should validate with secret1
        assert validate_csrf_token(token, session_id, secret1) is True

        # Should NOT validate with secret2
        assert validate_csrf_token(token, session_id, secret2) is False

    def test_token_uniqueness(self):
        """Test that generated tokens are unique."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Generate tokens with explicit timestamps to ensure uniqueness
        tokens = set()
        base_timestamp = int(time.time())

        for i in range(10):
            # Use explicit timestamps to guarantee uniqueness
            timestamp = base_timestamp + i
            token = generate_csrf_token(session_id, secret_key, timestamp=timestamp)
            assert token not in tokens, f"Token {token} was not unique (iteration {i})"
            tokens.add(token)

        assert len(tokens) == 10

    def test_token_tampering_detection(self):
        """Test that tampered tokens are rejected."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # Generate valid token
        token = generate_csrf_token(session_id, secret_key)

        # Tamper with different parts
        parts = token.split(":")

        # Tamper with timestamp
        tampered1 = f"9999999999:{parts[1]}:{parts[2]}"
        assert validate_csrf_token(tampered1, session_id, secret_key) is False

        # Tamper with user data
        tampered2 = f"{parts[0]}:tampered:{parts[2]}"
        assert validate_csrf_token(tampered2, session_id, secret_key) is False

        # Tamper with signature
        tampered3 = f"{parts[0]}:{parts[1]}:{'0' * 64}"
        assert validate_csrf_token(tampered3, session_id, secret_key) is False


class TestIntegrationScenarios:
    """Test real-world integration scenarios."""

    def test_web_form_protection_scenario(self):
        """Test typical web form CSRF protection scenario."""
        session_id = "sess-user123"
        secret_key = "web-app-secret"

        # 1. Generate token for form
        form_token = generate_csrf_token(
            session_id,
            secret_key,
            user_data={"form": "delete_account", "user_id": "123"},
        )

        # Debug: Let's manually verify the token structure
        parts = form_token.split(":")
        print(f"Token parts: {parts}")
        print(f"Timestamp: {parts[0]}")
        print(f"User data: {parts[1]}")
        print(f"Signature: {parts[2]}")

        # Test token info extraction first to see detailed error
        info = extract_csrf_token_info(form_token, session_id, secret_key)
        print(f"Token info error: {info.error}")

        # 2. User submits form with token
        # 3. Validate token on server
        is_valid = validate_csrf_token(form_token, session_id, secret_key)

        assert is_valid is True, f"Form token validation failed - {info.error}"

        # 4. Extract and verify action data
        assert info.is_valid is True, f"Token info extraction failed: {info.error}"
        assert info.user_data["form"] == "delete_account"
        assert info.user_data["user_id"] == "123"

    def test_api_request_protection_scenario(self):
        """Test API request CSRF protection scenario."""
        session_id = "sess-api456"
        secret_key = "api-secret-key"

        # 1. Generate encrypted token for API call
        api_token = generate_encrypted_csrf_token(
            session_id,
            secret_key,
            user_data={
                "endpoint": "/api/transfer",
                "method": "POST",
                "amount": 5000,
                "to_account": "acc-789",
            },
        )

        # 2. API validates token
        is_valid, api_data = validate_encrypted_csrf_token(
            api_token, session_id, secret_key
        )
        assert is_valid is True

        # 3. Verify API call data
        assert api_data["endpoint"] == "/api/transfer"
        assert api_data["method"] == "POST"
        assert api_data["amount"] == 5000
        assert api_data["to_account"] == "acc-789"

    def test_double_submit_cookie_scenario(self):
        """Test double submit cookie protection scenario."""
        session_id = "sess-cookie789"
        secret_key = "cookie-secret"

        # 1. Generate token pair for page load
        cookie_token, form_token = generate_double_submit_token(session_id, secret_key)

        # 2. Server sets cookie and includes form token
        # (In real scenario: response.set_cookie(...), template includes form_token)

        # 3. User submits form with both tokens
        # 4. Server validates both tokens
        is_valid = validate_double_submit_token(
            cookie_token, form_token, session_id, secret_key
        )
        assert is_valid is True

    def test_token_refresh_scenario(self):
        """Test token refresh scenario for long-running forms."""
        session_id = "sess-refresh"
        secret_key = "refresh-secret"

        # 1. Generate initial token
        old_token = generate_csrf_token(session_id, secret_key)

        # 2. Token is valid initially
        assert validate_csrf_token(old_token, session_id, secret_key) is True

        # 3. Time passes, check if refresh is needed
        info = extract_csrf_token_info(old_token, session_id, secret_key)
        refresh_needed = info.age_seconds > 1800  # 30 minutes

        if refresh_needed:
            # 4. Generate new token
            new_token = generate_csrf_token(session_id, secret_key)
            assert validate_csrf_token(new_token, session_id, secret_key) is True

        # For this test, token should still be fresh
        assert refresh_needed is False


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_malformed_token_handling(self):
        """Test handling of various malformed token formats."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        malformed_tokens = [
            "",  # Empty
            ":",  # Just separator
            "a:b",  # Too few parts
            "a:b:c:d",  # Too many parts
            "notanumber:data:signature",  # Invalid timestamp
            "123::signature",  # Missing user data (but valid)
            "123:data:",  # Missing signature
            "123:data:invalid_hex",  # Invalid signature format
        ]

        for token in malformed_tokens:
            # Should handle gracefully without exceptions
            result = validate_csrf_token(token, session_id, secret_key)
            assert result is False

            # Info extraction should also handle gracefully
            info = extract_csrf_token_info(token, session_id, secret_key)
            assert info.is_valid is False

    def test_edge_case_inputs(self):
        """Test edge case inputs."""
        session_id = "sess-abc123"
        secret_key = "test-secret-key"

        # None inputs
        with pytest.raises(ValueError):
            generate_csrf_token(None, secret_key)

        with pytest.raises(ValueError):
            generate_csrf_token(session_id, None)

        # Very long inputs
        long_session = "sess-" + "x" * 1000
        long_secret = "secret-" + "y" * 1000

        # Should handle long inputs without issues
        token = generate_csrf_token(long_session, long_secret)
        assert validate_csrf_token(token, long_session, long_secret) is True

        # Unicode inputs
        unicode_session = "sess-café"
        unicode_secret = "秘密鍵"

        # Should handle Unicode without issues
        token = generate_csrf_token(unicode_session, unicode_secret)
        assert validate_csrf_token(token, unicode_session, unicode_secret) is True


# Pytest fixtures
@pytest.fixture
def sample_session_data():
    """Fixture providing sample session data."""
    return {
        "session_id": "sess-test123",
        "secret_key": "test-secret-key-123",
        "user_data": {"action": "delete", "resource_id": "456"},
    }


@pytest.fixture
def csrf_token_samples(sample_session_data):
    """Fixture providing various CSRF token samples."""
    session_id = sample_session_data["session_id"]
    secret_key = sample_session_data["secret_key"]
    user_data = sample_session_data["user_data"]

    return {
        "basic": generate_csrf_token(session_id, secret_key),
        "with_data": generate_csrf_token(session_id, secret_key, user_data=user_data),
        "encrypted": generate_encrypted_csrf_token(session_id, secret_key, user_data),
        "double_submit": generate_double_submit_token(session_id, secret_key),
    }


# Parametrized tests
@pytest.mark.parametrize("token_type", ["basic", "with_data"])
def test_token_validation_parametrized(
    token_type, csrf_token_samples, sample_session_data
):
    """Test token validation for different token types."""
    session_id = sample_session_data["session_id"]
    secret_key = sample_session_data["secret_key"]

    if token_type == "double_submit":
        cookie_token, form_token = csrf_token_samples[token_type]
        assert (
            validate_double_submit_token(
                cookie_token, form_token, session_id, secret_key
            )
            is True
        )
    elif token_type == "encrypted":
        token = csrf_token_samples[token_type]
        is_valid, _ = validate_encrypted_csrf_token(token, session_id, secret_key)
        assert is_valid is True
    else:
        token = csrf_token_samples[token_type]
        assert validate_csrf_token(token, session_id, secret_key) is True


@pytest.mark.parametrize("max_age", [60, 300, 1800, 3600, 7200])
def test_token_expiration_parametrized(max_age, sample_session_data):
    """Test token expiration with different max ages."""
    session_id = sample_session_data["session_id"]
    secret_key = sample_session_data["secret_key"]

    # Create token from 30 minutes ago
    old_timestamp = int(time.time()) - 1800
    token = generate_csrf_token(session_id, secret_key, old_timestamp)

    # Should pass or fail based on max_age
    expected_valid = max_age >= 1800
    actual_valid = validate_csrf_token(
        token, session_id, secret_key, max_age_seconds=max_age
    )

    assert actual_valid == expected_valid
