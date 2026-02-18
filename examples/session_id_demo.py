#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# examples/session_id_demo.py
"""
Session ID Generation and Validation Examples

This script demonstrates how to use the chuk_sessions security utilities
for generating and validating secure session IDs across different protocols.

Features demonstrated:
- Basic session ID generation for different protocols
- Custom format configuration
- Security validation and analysis
- Protocol compliance checking
- Entropy requirements and validation
- Real-world usage patterns
"""

import sys
import os

# Add the parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chuk_sessions.utils.security.session_ids import (
    generate_secure_session_id,
    validate_session_id_format,
    estimate_entropy,
    analyze_session_id_strength,
)


def print_section(title: str):
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f"🔐 {title}")
    print(f"{'=' * 60}")


def print_subsection(title: str):
    """Print a formatted subsection header."""
    print(f"\n{'-' * 40}")
    print(f"📝 {title}")
    print(f"{'-' * 40}")


def demonstrate_basic_generation():
    """Demonstrate basic session ID generation for different protocols."""
    print_section("Basic Session ID Generation")

    protocols = ["generic", "mcp", "http", "websocket", "uuid", "jwt"]

    for protocol in protocols:
        print_subsection(f"{protocol.upper()} Protocol")

        try:
            # Generate multiple session IDs to show uniqueness
            session_ids = []
            for i in range(3):
                session_id = generate_secure_session_id(protocol)
                session_ids.append(session_id)
                print(f"  Example {i + 1}: {session_id}")

            # Verify uniqueness
            unique_ids = set(session_ids)
            print(
                f"  ✓ Generated {len(session_ids)} unique IDs: {len(unique_ids) == len(session_ids)}"
            )

            # Show entropy
            entropy = estimate_entropy(session_ids[0])
            print(f"  📊 Estimated entropy: {entropy:.1f} bits")

        except Exception as e:
            print(f"  ❌ Error: {e}")


def demonstrate_custom_formats():
    """Demonstrate custom session ID formats."""
    print_section("Custom Format Examples")

    custom_formats = [
        {
            "name": "High Security API Key",
            "format": {
                "length": 40,
                "alphabet": "ABCDEF0123456789",
                "prefix": "sk",
                "separator": "_",
            },
        },
        {
            "name": "Short Development Token",
            "format": {
                "length": 16,
                "alphabet": "abcdefghijklmnopqrstuvwxyz0123456789",
                "prefix": "dev",
                "separator": "-",
            },
        },
        {
            "name": "Alphanumeric Session",
            "format": {
                "length": 24,
                "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "prefix": "sess",
                "separator": "_",
            },
        },
        {
            "name": "Numeric PIN (Extended)",
            "format": {
                "length": 16,
                "alphabet": "0123456789",
                "prefix": "pin",
                "separator": "_",
            },
        },
    ]

    for config in custom_formats:
        print_subsection(config["name"])

        try:
            session_id = generate_secure_session_id("custom", config["format"])
            print(f"  Generated: {session_id}")

            # Analyze the generated ID
            analysis = analyze_session_id_strength(session_id)
            print(f"  Length: {analysis['length']} characters")
            print(f"  Entropy: {analysis['entropy_bits']} bits")
            print(f"  Strength: {analysis['strength']}")

            if analysis["recommendations"]:
                print("  ⚠️  Recommendations:")
                for rec in analysis["recommendations"]:
                    print(f"     - {rec}")
            else:
                print("  ✓ No security recommendations")

        except Exception as e:
            print(f"  ❌ Error: {e}")


def demonstrate_validation():
    """Demonstrate session ID validation."""
    print_section("Session ID Validation")

    test_cases = [
        # Valid cases
        {
            "session_id": "mcp-f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "protocol": "mcp",
            "description": "Valid MCP UUID format",
        },
        {
            "session_id": "http-X9zK2mN8qP4vR7sT5wY1uC3eI6oL9rE2",
            "protocol": "http",
            "description": "Valid HTTP session",
        },
        {
            "session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "protocol": "uuid",
            "description": "Valid UUID",
        },
        # Invalid cases
        {
            "session_id": "weak123",
            "protocol": "generic",
            "description": "Too short and weak",
        },
        {
            "session_id": "mcp-café",
            "protocol": "mcp",
            "description": "Invalid MCP characters (non-ASCII)",
        },
        {"session_id": "", "protocol": "generic", "description": "Empty session ID"},
        {
            "session_id": "aaaaaaaaaaaaaaaa",
            "protocol": "generic",
            "description": "No character diversity",
        },
    ]

    for test in test_cases:
        print_subsection(test["description"])

        session_id = test["session_id"]
        protocol = test["protocol"]

        print(f"  Session ID: '{session_id}'")
        print(f"  Protocol: {protocol}")

        # Basic validation
        is_valid = validate_session_id_format(session_id, protocol)
        print(f"  Valid: {'✓' if is_valid else '❌'}")

        if session_id:  # Skip analysis for empty strings
            # Detailed analysis
            analysis = analyze_session_id_strength(session_id)
            if analysis.get("valid", False):
                print(f"  Entropy: {analysis['entropy_bits']} bits")
                print(f"  Strength: {analysis['strength']}")
                print(f"  Character diversity: {analysis['character_diversity']}")

                if analysis["patterns_detected"]:
                    print(
                        f"  ⚠️  Patterns detected: {', '.join(analysis['patterns_detected'])}"
                    )
            else:
                print(f"  ❌ Analysis failed: {analysis.get('error', 'Unknown error')}")


def demonstrate_entropy_analysis():
    """Demonstrate entropy analysis and security assessment."""
    print_section("Entropy Analysis")

    # Generate session IDs with different entropy levels
    entropy_examples = [
        {
            "name": "High Entropy (UUID)",
            "generator": lambda: generate_secure_session_id("uuid"),
        },
        {
            "name": "Good Entropy (MCP)",
            "generator": lambda: generate_secure_session_id("mcp"),
        },
        {
            "name": "Medium Entropy (Custom)",
            "generator": lambda: generate_secure_session_id(
                "custom",
                {
                    "length": 20,
                    "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    "prefix": "med",
                    "separator": "-",
                },
            ),
        },
        {
            "name": "Lower Entropy (Shorter)",
            "generator": lambda: generate_secure_session_id(
                "custom",
                {
                    "length": 12,
                    "alphabet": "abcdefghijklmnopqrstuvwxyz",
                    "prefix": "low",
                    "separator": "-",
                },
            ),
        },
    ]

    for example in entropy_examples:
        print_subsection(example["name"])

        try:
            session_id = example["generator"]()
            analysis = analyze_session_id_strength(session_id)

            print(f"  Session ID: {session_id}")
            print(f"  Length: {analysis['length']} characters")
            print(f"  Unique chars: {analysis['unique_characters']}")
            print(f"  Estimated entropy: {analysis['entropy_bits']} bits")
            print(f"  Strength rating: {analysis['strength']}")
            print(f"  Character diversity: {analysis['character_diversity']}")

            # Protocol compliance
            compliant_protocols = [
                p
                for p, compliant in analysis["protocol_compliance"].items()
                if compliant
            ]
            if compliant_protocols:
                print(f"  ✓ Protocol compliance: {', '.join(compliant_protocols)}")

            # Recommendations
            if analysis["recommendations"]:
                print("  💡 Recommendations:")
                for rec in analysis["recommendations"]:
                    print(f"     - {rec}")

        except Exception as e:
            print(f"  ❌ Error: {e}")


def demonstrate_real_world_usage():
    """Demonstrate real-world usage patterns."""
    print_section("Real-World Usage Patterns")

    scenarios = [
        {
            "name": "MCP Server Session",
            "description": "Creating a session for MCP protocol communication",
            "code": lambda: generate_secure_session_id("mcp"),
            "validation": lambda sid: validate_session_id_format(sid, "mcp"),
        },
        {
            "name": "Web Application Session",
            "description": "HTTP session for web application user",
            "code": lambda: generate_secure_session_id("http"),
            "validation": lambda sid: validate_session_id_format(sid, "http"),
        },
        {
            "name": "API Authentication Token",
            "description": "Long-lived API token with high security",
            "code": lambda: generate_secure_session_id(
                "custom",
                {
                    "length": 48,
                    "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    "prefix": "ak",
                    "separator": "_",
                },
            ),
            "validation": lambda sid: validate_session_id_format(
                sid, "generic", min_entropy_bits=256
            ),
        },
        {
            "name": "Temporary Verification Code",
            "description": "Short-lived code for email verification",
            "code": lambda: generate_secure_session_id(
                "custom",
                {
                    "length": 16,
                    "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    "prefix": "verify",
                    "separator": "_",
                },
            ),
            "validation": lambda sid: validate_session_id_format(
                sid, "generic", min_entropy_bits=64, strict_mode=False
            ),
        },
        {
            "name": "WebSocket Connection ID",
            "description": "Session ID for WebSocket connection tracking",
            "code": lambda: generate_secure_session_id("websocket"),
            "validation": lambda sid: validate_session_id_format(sid, "websocket"),
        },
    ]

    for scenario in scenarios:
        print_subsection(scenario["name"])
        print(f"  Purpose: {scenario['description']}")

        try:
            # Generate session ID
            session_id = scenario["code"]()
            print(f"  Generated: {session_id}")

            # Validate
            is_valid = scenario["validation"](session_id)
            print(f"  Validation: {'✓ PASS' if is_valid else '❌ FAIL'}")

            # Quick analysis
            entropy = estimate_entropy(session_id)
            print(f"  Entropy: {entropy:.1f} bits")

        except Exception as e:
            print(f"  ❌ Error: {e}")


def demonstrate_security_comparison():
    """Compare security properties of different approaches."""
    print_section("Security Comparison")

    # Generate examples using different methods
    methods = [
        ("Sequential", "user_session_001"),
        ("Timestamp-based", f"sess_{int(__import__('time').time())}"),
        ("Simple Random", "sess_abc123def456"),
        ("CHUK Sessions Generic", generate_secure_session_id("generic")),
        ("CHUK Sessions MCP", generate_secure_session_id("mcp")),
        (
            "CHUK Sessions High Entropy",
            generate_secure_session_id(
                "custom",
                {
                    "length": 32,
                    "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*",
                    "prefix": "secure",
                    "separator": "_",
                },
            ),
        ),
    ]

    print(f"{'Method':<25} {'Example':<35} {'Entropy':<10} {'Strength':<12} {'Issues'}")
    print("-" * 100)

    for method_name, session_id in methods:
        try:
            analysis = analyze_session_id_strength(session_id)
            entropy = analysis.get("entropy_bits", 0)
            strength = analysis.get("strength", "unknown")
            issues = len(analysis.get("patterns_detected", [])) + len(
                analysis.get("recommendations", [])
            )

            # Truncate long session IDs for display
            display_id = session_id[:30] + "..." if len(session_id) > 30 else session_id

            print(
                f"{method_name:<25} {display_id:<35} {entropy:<10.1f} {strength:<12} {issues}"
            )

        except Exception:
            print(f"{method_name:<25} {'ERROR':<35} {'N/A':<10} {'N/A':<12} {'∞'}")


def main():
    """Run all demonstrations."""
    print("🔐 CHUK Sessions - Session ID Security Examples")
    print("=" * 60)
    print("This script demonstrates secure session ID generation and validation.")

    try:
        demonstrate_basic_generation()
        demonstrate_custom_formats()
        demonstrate_validation()
        demonstrate_entropy_analysis()
        demonstrate_real_world_usage()
        demonstrate_security_comparison()

        print_section("Summary")
        print("✅ All demonstrations completed successfully!")
        print("\n💡 Key Takeaways:")
        print("   • Use generate_secure_session_id() for cryptographic security")
        print("   • Choose appropriate protocols (MCP, HTTP, WebSocket, etc.)")
        print("   • Validate session IDs with validate_session_id_format()")
        print("   • Analyze security with analyze_session_id_strength()")
        print("   • Aim for 128+ bits of entropy")
        print("   • Avoid predictable patterns and short lengths")

    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
