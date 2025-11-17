#!/usr/bin/env python3
"""
🚀 CHUK Sessions - Developer Quickstart

This interactive script demonstrates the key features of CHUK Sessions.
Perfect for getting started in under 5 minutes!

Run with: python quickstart.py
"""

import asyncio
import os
import time
from datetime import datetime

# Ensure we're using memory provider for quickstart
os.environ["SESSION_PROVIDER"] = "memory"

from chuk_sessions import SessionManager
from chuk_sessions.provider_factory import factory_for_env


def print_header(title: str):
    """Print a nice section header."""
    print(f"\n{'=' * 60}")
    print(f"✨ {title}")
    print(f"{'=' * 60}\n")


def print_step(step: int, description: str):
    """Print a numbered step."""
    print(f"\n{step}️⃣  {description}")
    print("-" * 40)


async def quickstart():
    """Interactive quickstart demonstration."""
    print("\n🎯 Welcome to CHUK Sessions!")
    print("This quickstart will show you the basics in under 2 minutes.\n")

    # Ask if they want to continue
    input("Press Enter to start the demo... ")

    # ========================================================================
    # PART 1: Basic Session Storage (Low-Level API)
    # ========================================================================
    print_header("Part 1: Basic Session Storage (Low-Level API)")

    print_step(1, "Creating a session provider")
    print("The low-level API is perfect for simple key-value storage with TTL.")

    session_factory = factory_for_env()
    print("✅ Using memory provider (great for development!)")

    async with session_factory() as session:
        print_step(2, "Storing data with expiration")

        # Store some data
        await session.setex("user:123", 300, "Alice Johnson")
        await session.setex("api_key:xyz", 60, "secret_token_abc123")
        await session.setex("cache:result", 30, '{"data": "expensive computation"}')

        print("📝 Stored:")
        print("  • user:123 → 'Alice Johnson' (expires in 5 minutes)")
        print("  • api_key:xyz → 'secret_token_abc123' (expires in 1 minute)")
        print("  • cache:result → JSON data (expires in 30 seconds)")

        print_step(3, "Retrieving data")

        user = await session.get("user:123")
        api_key = await session.get("api_key:xyz")

        print(f"👤 User: {user}")
        print(f"🔑 API Key: {api_key}")

        print("\n💡 TIP: Data automatically expires after the TTL!")

    input("\nPress Enter to continue to Session Management... ")

    # ========================================================================
    # PART 2: Session Management (High-Level API)
    # ========================================================================
    print_header("Part 2: Session Management (High-Level API)")

    print("The high-level API provides complete session lifecycle management.")

    print_step(4, "Creating a SessionManager")

    # Create manager for a web app
    app = SessionManager(
        sandbox_id="my-awesome-app",
        default_ttl_hours=8,  # Work day session
    )
    print(f"✅ Created SessionManager for sandbox: '{app.sandbox_id}'")

    print_step(5, "Creating user sessions")

    # Create sessions for different users
    alice_session = await app.allocate_session(
        user_id="alice",
        custom_metadata={
            "role": "admin",
            "login_time": datetime.now().isoformat(),
            "ip": "192.168.1.100",
        },
    )

    bob_session = await app.allocate_session(
        user_id="bob", custom_metadata={"role": "user", "plan": "premium"}
    )

    print(f"👩 Alice's session: {alice_session}")
    print(f"👨 Bob's session: {bob_session}")

    print_step(6, "Working with sessions")

    # Validate session
    is_valid = await app.validate_session(alice_session)
    print(f"✅ Alice's session valid? {is_valid}")

    # Get session info
    info = await app.get_session_info(alice_session)
    print("\n📋 Alice's session info:")
    print(f"  • User ID: {info['user_id']}")
    print(f"  • Created: {info['created_at']}")
    print(f"  • Expires: {info['expires_at']}")
    print(f"  • Metadata: {info['custom_metadata']}")

    # Update metadata
    await app.update_session_metadata(
        alice_session, {"last_activity": datetime.now().isoformat(), "pages_viewed": 5}
    )
    print("\n✏️  Updated Alice's metadata with activity info")

    input("\nPress Enter to see multi-tenant isolation... ")

    # ========================================================================
    # PART 3: Multi-Tenant Isolation
    # ========================================================================
    print_header("Part 3: Multi-Tenant Isolation")

    print("CHUK Sessions provides perfect isolation between different apps/tenants.")

    print_step(7, "Creating isolated sandboxes")

    # Different apps = different sandboxes
    app_a = SessionManager(sandbox_id="customer-portal")
    app_b = SessionManager(sandbox_id="admin-panel")

    # Same user, different apps = different sessions
    user_in_portal = await app_a.allocate_session(user_id="john@example.com")
    user_in_admin = await app_b.allocate_session(user_id="john@example.com")

    print("🏢 Created isolated environments:")
    print(f"  • Customer Portal: {user_in_portal}")
    print(f"  • Admin Panel: {user_in_admin}")
    print("\n✅ Same user, but completely isolated sessions!")

    # ========================================================================
    # PART 4: Real-World Examples
    # ========================================================================
    input("\nPress Enter to see real-world examples... ")

    print_header("Part 4: Real-World Examples")

    print_step(8, "Web App Session")

    web_app = SessionManager(sandbox_id="web-app")

    # Simulate login
    session_id = await web_app.allocate_session(
        user_id="user@example.com",
        ttl_hours=8,
        custom_metadata={
            "login_method": "oauth",
            "permissions": ["read", "write"],
            "theme": "dark",
        },
    )
    print(f"🌐 Created web session: {session_id[:20]}...")

    print_step(9, "API Rate Limiting")

    api_gateway = SessionManager(sandbox_id="api-gateway", default_ttl_hours=1)

    # Create rate limit session
    client_session = await api_gateway.allocate_session(
        user_id="client_xyz",
        custom_metadata={"tier": "premium", "rate_limit": 1000, "requests_made": 0},
    )

    # Simulate API calls
    for i in range(3):
        info = await api_gateway.get_session_info(client_session)
        requests = info["custom_metadata"]["requests_made"]
        await api_gateway.update_session_metadata(
            client_session, {"requests_made": requests + 1, "last_request": time.time()}
        )

    final_info = await api_gateway.get_session_info(client_session)
    print(
        f"⚡ API Client: {final_info['custom_metadata']['requests_made']} requests made"
    )

    print_step(10, "Temporary Verification Codes")

    # Using low-level API for simple temporary storage
    async with session_factory() as session:
        verification_code = "ABC123"
        await session.setex("verify:user@example.com", 600, verification_code)
        print("📧 Stored verification code for 10 minutes")

    # ========================================================================
    # Summary
    # ========================================================================
    print_header("🎉 Quickstart Complete!")

    print("You've learned:")
    print("✅ Low-level API for simple key-value storage")
    print("✅ High-level SessionManager for complete lifecycle management")
    print("✅ Multi-tenant isolation with sandboxes")
    print("✅ Real-world usage patterns")

    print("\n📚 Next steps:")
    print("1. Check out the examples/ directory for more demos")
    print("2. Run the performance test: python examples/performance_test.py")
    print("3. Try Redis provider: export SESSION_PROVIDER=redis")
    print("4. Read the comprehensive README for all features")

    print("\n🚀 Happy coding with CHUK Sessions!")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🚀 CHUK SESSIONS - DEVELOPER QUICKSTART")
    print("=" * 60)

    try:
        asyncio.run(quickstart())
    except KeyboardInterrupt:
        print("\n\n👋 Thanks for trying CHUK Sessions!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("💡 Make sure you have chuk-sessions installed:")
        print("   pip install chuk-sessions")
