#!/usr/bin/env python3
"""
CSRF Protection Demo Script

This script demonstrates the usage of all CSRF protection methods:
1. Basic HMAC-based tokens
2. Double Submit Cookie tokens
3. Encrypted tokens
4. Token information extraction
5. Expiration checking

Run this script to see how each method works in practice.
"""

import time
from typing import Any

# Import the CSRF utilities
try:
    # Try importing from your module first
    from chuk_sessions.utils.security.csrf import (
        generate_csrf_token,
        validate_csrf_token,
        generate_double_submit_token,
        validate_double_submit_token,
        generate_encrypted_csrf_token,
        validate_encrypted_csrf_token,
        extract_csrf_token_info,
        is_csrf_token_expired,
    )
except ImportError:
    # If that fails, try importing from local file
    try:
        import sys
        import os

        # Add the parent directory to path to find the csrf module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        from chuk_sessions.utils.security.csrf import (
            generate_csrf_token,
            validate_csrf_token,
            generate_double_submit_token,
            validate_double_submit_token,
            generate_encrypted_csrf_token,
            validate_encrypted_csrf_token,
            extract_csrf_token_info,
            is_csrf_token_expired,
        )
    except ImportError as e:
        print(f"❌ Could not import CSRF module: {e}")
        print("\nPlease ensure:")
        print("1. The csrf.py file is in the correct location")
        print("2. Or adjust the import path in this demo script")
        print("3. Or run from the correct directory")
        sys.exit(1)

# ============================================================================
# DEMO SCRIPT
# ============================================================================


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print(f"{'=' * 60}")


def print_result(description: str, result: Any, success: bool = True):
    """Print a formatted result."""
    status = "✓" if success else "✗"
    print(f"{status} {description}: {result}")


def demo_basic_hmac_tokens():
    """Demonstrate basic HMAC-based CSRF tokens."""
    print_section("Basic HMAC-based CSRF Tokens")

    # Setup
    session_id = "user_session_abc123"
    secret_key = "super_secret_server_key_2024"

    print(f"Session ID: {session_id}")
    print(f"Secret Key: {secret_key[:10]}...")

    # 1. Generate a simple token
    print("\n1. Generate Simple Token:")
    token = generate_csrf_token(session_id, secret_key)
    print_result("Generated token", token[:50] + "...")

    # 2. Validate the token
    print("\n2. Validate Token:")
    is_valid = validate_csrf_token(token, session_id, secret_key)
    print_result("Token validation", is_valid, is_valid)

    # 3. Generate token with user data
    print("\n3. Generate Token with User Data:")
    user_data = {"action": "delete_user", "user_id": "12345", "admin_level": 2}
    token_with_data = generate_csrf_token(session_id, secret_key, user_data=user_data)
    print_result("User data", user_data)
    print_result("Token with data", token_with_data[:50] + "...")

    # 4. Extract token information
    print("\n4. Extract Token Information:")
    token_info = extract_csrf_token_info(token_with_data, session_id, secret_key)
    print_result("Session ID", token_info.session_id)
    print_result("Token age (seconds)", token_info.age_seconds)
    print_result("User data", token_info.user_data)
    print_result("Is valid", token_info.is_valid, token_info.is_valid)

    # 5. Test invalid token
    print("\n5. Test Invalid Token:")
    invalid_token = token_with_data[:-10] + "tampered123"
    is_valid_tampered = validate_csrf_token(invalid_token, session_id, secret_key)
    print_result("Tampered token validation", is_valid_tampered, not is_valid_tampered)

    # 6. Test wrong session ID
    print("\n6. Test Wrong Session ID:")
    wrong_session = validate_csrf_token(token, "wrong_session", secret_key)
    print_result("Wrong session validation", wrong_session, not wrong_session)

    return token_with_data


def demo_double_submit_tokens():
    """Demonstrate double submit cookie CSRF tokens."""
    print_section("Double Submit Cookie CSRF Tokens")

    # Setup
    session_id = "user_session_xyz789"
    secret_key = "another_secret_key_2024"

    print(f"Session ID: {session_id}")
    print(f"Secret Key: {secret_key[:10]}...")

    # 1. Generate double submit tokens
    print("\n1. Generate Double Submit Tokens:")
    cookie_token, form_token = generate_double_submit_token(session_id, secret_key)
    print_result("Cookie token", cookie_token[:50] + "...")
    print_result("Form token", form_token[:50] + "...")

    # 2. Validate the token pair
    print("\n2. Validate Token Pair:")
    is_valid_pair = validate_double_submit_token(
        cookie_token, form_token, session_id, secret_key
    )
    print_result("Token pair validation", is_valid_pair, is_valid_pair)

    # 3. Test with mismatched tokens
    print("\n3. Test Mismatched Tokens:")
    _, wrong_form_token = generate_double_submit_token(session_id, secret_key)
    is_mismatched = validate_double_submit_token(
        cookie_token, wrong_form_token, session_id, secret_key
    )
    print_result("Mismatched tokens", is_mismatched, not is_mismatched)

    # 4. Generate with custom cookie value
    print("\n4. Custom Cookie Value:")
    custom_cookie_val = "my_custom_cookie_value_123"
    custom_cookie, custom_form = generate_double_submit_token(
        session_id, secret_key, custom_cookie_val
    )
    print_result("Custom cookie token", custom_cookie[:50] + "...")

    is_custom_valid = validate_double_submit_token(
        custom_cookie, custom_form, session_id, secret_key
    )
    print_result("Custom token validation", is_custom_valid, is_custom_valid)


def demo_encrypted_tokens():
    """Demonstrate encrypted CSRF tokens."""
    print_section("Encrypted CSRF Tokens (Stateless)")

    # Setup
    session_id = "stateless_session_def456"
    secret_key = "encryption_secret_key_2024"

    print(f"Session ID: {session_id}")
    print(f"Secret Key: {secret_key[:10]}...")

    # 1. Generate encrypted token
    print("\n1. Generate Encrypted Token:")
    user_data = {
        "action": "transfer_funds",
        "amount": 1500.00,
        "recipient": "account_789",
        "currency": "USD",
    }

    encrypted_token = generate_encrypted_csrf_token(
        session_id, secret_key, user_data=user_data
    )
    print_result("User data", user_data)
    print_result("Encrypted token", encrypted_token[:60] + "...")

    # 2. Validate and decrypt token
    print("\n2. Validate and Decrypt Token:")
    is_valid, decrypted_data = validate_encrypted_csrf_token(
        encrypted_token, session_id, secret_key
    )
    print_result("Token validation", is_valid, is_valid)
    print_result("Decrypted data", decrypted_data)

    # 3. Test with wrong session
    print("\n3. Test Wrong Session:")
    wrong_valid, wrong_data = validate_encrypted_csrf_token(
        encrypted_token, "wrong_session", secret_key
    )
    print_result("Wrong session validation", wrong_valid, not wrong_valid)
    print_result("Wrong session data", wrong_data)

    # 4. Generate token without user data
    print("\n4. Token Without User Data:")
    simple_encrypted = generate_encrypted_csrf_token(session_id, secret_key)
    print_result("Simple encrypted token", simple_encrypted[:60] + "...")

    simple_valid, simple_data = validate_encrypted_csrf_token(
        simple_encrypted, session_id, secret_key
    )
    print_result("Simple token validation", simple_valid, simple_valid)
    print_result("Simple token data", simple_data)


def demo_expiration_handling():
    """Demonstrate token expiration handling."""
    print_section("Token Expiration Handling")

    # Setup
    session_id = "expiry_test_session"
    secret_key = "expiry_test_secret_key"

    # 1. Generate token with past timestamp
    print("\n1. Generate Expired Token:")
    past_timestamp = int(time.time()) - 7200  # 2 hours ago
    expired_token = generate_csrf_token(
        session_id, secret_key, timestamp=past_timestamp
    )
    print_result("Expired token", expired_token[:50] + "...")

    # 2. Check if token is expired
    print("\n2. Check Token Expiration:")
    is_expired = is_csrf_token_expired(expired_token, session_id, secret_key, 3600)
    print_result("Is token expired (1 hour limit)", is_expired, is_expired)

    # 3. Validate expired token
    print("\n3. Validate Expired Token:")
    is_valid_expired = validate_csrf_token(
        expired_token, session_id, secret_key, max_age_seconds=3600
    )
    print_result("Expired token validation", is_valid_expired, not is_valid_expired)

    # 4. Generate fresh token
    print("\n4. Fresh Token Comparison:")
    fresh_token = generate_csrf_token(session_id, secret_key)
    fresh_info = extract_csrf_token_info(fresh_token, session_id, secret_key)
    expired_info = extract_csrf_token_info(expired_token, session_id, secret_key)

    print_result("Fresh token age", f"{fresh_info.age_seconds} seconds")
    print_result("Expired token age", f"{expired_info.age_seconds} seconds")
    print_result("Fresh token valid", fresh_info.is_valid, fresh_info.is_valid)
    print_result("Expired token valid", expired_info.is_valid, expired_info.is_valid)


def demo_token_info_extraction():
    """Demonstrate comprehensive token information extraction."""
    print_section("Token Information Extraction")

    # Setup
    session_id = "info_extraction_session"
    secret_key = "info_extraction_secret"

    # Generate token with rich user data
    user_data = {
        "form_id": "user_profile_form",
        "fields": ["email", "phone", "address"],
        "csrf_version": "2.0",
        "client_ip": "192.168.1.100",
    }

    token = generate_csrf_token(session_id, secret_key, user_data=user_data)

    # Extract comprehensive information
    print("\n1. Comprehensive Token Info:")
    token_info = extract_csrf_token_info(token, session_id, secret_key)

    info_dict = token_info.to_dict()
    for key, value in info_dict.items():
        print_result(f"  {key}", value)

    # Test different validation scenarios
    print("\n2. Validation Scenarios:")

    # Require user data
    requires_data = validate_csrf_token(
        token, session_id, secret_key, require_user_data=True
    )
    print_result("Validation (requires user data)", requires_data, requires_data)

    # Token without user data
    simple_token = generate_csrf_token(session_id, secret_key)
    requires_data_fail = validate_csrf_token(
        simple_token, session_id, secret_key, require_user_data=True
    )
    print_result(
        "Simple token (requires user data)", requires_data_fail, not requires_data_fail
    )


def demo_real_world_scenario():
    """Demonstrate a real-world web application scenario."""
    print_section("Real-World Web Application Scenario")

    print("Simulating a web application with multiple forms and CSRF protection...")

    # Application setup
    app_secret = "my_web_app_secret_key_2024"

    # User logs in
    user_session = "user_john_doe_session_456"
    print(f"\n👤 User logs in with session: {user_session}")

    # 1. Profile update form
    print("\n📝 Profile Update Form:")
    profile_data = {
        "form": "profile_update",
        "allowed_fields": ["name", "email", "phone"],
    }
    profile_token = generate_csrf_token(
        user_session, app_secret, user_data=profile_data
    )
    print_result("Profile form token", profile_token[:40] + "...")

    # Simulate form submission
    print("\n   Form submission validation:")
    profile_valid = validate_csrf_token(profile_token, user_session, app_secret)
    print_result("   Profile form valid", profile_valid, profile_valid)

    # 2. Money transfer form (high security)
    print("\n💰 Money Transfer Form (Double Submit):")
    transfer_cookie, transfer_form = generate_double_submit_token(
        user_session, app_secret
    )
    print_result("Transfer cookie token", transfer_cookie[:40] + "...")
    print_result("Transfer form token", transfer_form[:40] + "...")

    # Simulate transfer submission
    print("\n   Transfer submission validation:")
    transfer_valid = validate_double_submit_token(
        transfer_cookie, transfer_form, user_session, app_secret
    )
    print_result("   Transfer valid", transfer_valid, transfer_valid)

    # 3. API call with encrypted token
    print("\n🔒 API Call (Encrypted Token):")
    api_data = {
        "endpoint": "/api/sensitive-data",
        "method": "POST",
        "permissions": ["read", "write"],
    }
    api_token = generate_encrypted_csrf_token(user_session, app_secret, api_data)
    print_result("API token", api_token[:50] + "...")

    # Simulate API validation
    print("\n   API call validation:")
    api_valid, api_extracted = validate_encrypted_csrf_token(
        api_token, user_session, app_secret
    )
    print_result("   API token valid", api_valid, api_valid)
    print_result("   API permissions", api_extracted.get("permissions", []))

    # 4. Simulate attack scenarios
    print("\n🚨 Attack Simulation:")

    # CSRF attack with stolen token but wrong session
    attacker_session = "attacker_session_999"
    attack_result = validate_csrf_token(profile_token, attacker_session, app_secret)
    print_result("   Attack with stolen token", attack_result, not attack_result)

    # Token tampering
    tampered_token = profile_token[:-5] + "HACK!"
    tamper_result = validate_csrf_token(tampered_token, user_session, app_secret)
    print_result("   Tampered token attack", tamper_result, not tamper_result)

    # Replay attack with old token
    old_timestamp = int(time.time()) - 7200  # 2 hours old
    old_token = generate_csrf_token(user_session, app_secret, timestamp=old_timestamp)
    replay_result = validate_csrf_token(
        old_token, user_session, app_secret, max_age_seconds=3600
    )
    print_result("   Replay attack (old token)", replay_result, not replay_result)


def main():
    """Run all CSRF protection demos."""
    print("🔐 CSRF Protection Utilities Demo")
    print("This demo shows how to use all CSRF protection methods.")

    try:
        # Run all demos
        demo_basic_hmac_tokens()
        demo_double_submit_tokens()
        demo_encrypted_tokens()
        demo_expiration_handling()
        demo_token_info_extraction()
        demo_real_world_scenario()

        # Summary
        print_section("Demo Complete! 🎉")
        print("All CSRF protection methods demonstrated successfully.")
        print("\nKey takeaways:")
        print("• Basic HMAC tokens: Simple and effective for most forms")
        print("• Double submit: Extra security for sensitive operations")
        print("• Encrypted tokens: Stateless operation with embedded data")
        print("• Always validate tokens server-side")
        print("• Use appropriate expiration times")
        print("• Handle errors gracefully")

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        print("Make sure the CSRF module is properly imported and configured.")


if __name__ == "__main__":
    main()
