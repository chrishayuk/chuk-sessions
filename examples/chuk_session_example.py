#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CHUK Sessions Example Script  –  **session-only edition**

Demonstrates:

• Low-level provider usage (memory / redis)
• High-level SessionManager API (allocate, validate, metadata, TTL)
• Multi-sandbox isolation (multi-tenant)
• Real-world session scenarios (web app, MCP server, API gateway)
• Error handling & admin helpers

No artifact / grid helpers are touched here.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict

from chuk_sessions.provider_factory import factory_for_env
from chuk_sessions.session_manager import SessionManager


# ────────────────────────────────────────────────────────────────────
# 1.  Low-level provider demo
# ────────────────────────────────────────────────────────────────────
async def demonstrate_basic_providers():
    print("=" * 70)
    print("BASIC PROVIDER DEMONSTRATION (Lower-Level API)")
    print("=" * 70)

    os.environ["SESSION_PROVIDER"] = "memory"
    session_factory = factory_for_env()

    async with session_factory() as session:
        print("✓ Memory provider created")

        # Store data with TTLs
        print("\n📝 Storing basic session data...")
        await session.setex(
            "user:123",
            60,
            json.dumps(
                {
                    "user_id": "123",
                    "username": "alice",
                    "role": "admin",
                    "login_time": "2024-01-01T10:00:00Z",
                }
            ),
        )
        await session.setex("temp_token", 5, "abc123def456")
        print("   • user:123  (60 s)")
        print("   • temp_token (5 s)")

        # Retrieve
        print("\n📖 Retrieving stored data...")
        user_data = await session.get("user:123")
        token = await session.get("temp_token")
        print(f"   • user:123  → {json.loads(user_data)['username']}")
        print(f"   • temp_token → {token}")

        # Wait for token expiry
        print("\n⏰ Waiting 6 s for temp_token to expire…")
        await asyncio.sleep(6)
        print(f"   • temp_token after 6 s → {await session.get('temp_token')}")
        print(f"   • user:123 still valid → {await session.get('user:123') is not None}")


# ────────────────────────────────────────────────────────────────────
# 2.  High-level SessionManager demo
# ────────────────────────────────────────────────────────────────────
async def demonstrate_session_manager():
    print("\n" + "=" * 70)
    print("SESSION MANAGER DEMONSTRATION (High-Level API)")
    print("=" * 70)

    os.environ["SESSION_PROVIDER"] = "memory"
    sm = SessionManager(sandbox_id="demo-app", default_ttl_hours=24)
    print("✓ SessionManager created for sandbox: demo-app")

    # ── Lifecycle
    print("\n📝 Session lifecycle…")
    alice = await sm.allocate_session(
        user_id="alice",
        ttl_hours=2,
        custom_metadata={"role": "admin", "department": "engineering"},
    )
    bob = await sm.allocate_session(
        user_id="bob",
        custom_metadata={"role": "user", "department": "marketing"},
    )
    anon = await sm.allocate_session()
    print(f"   • Alice → {alice}")
    print(f"   • Bob   → {bob}")
    print(f"   • Anon  → {anon}")

    # ── Validation & info
    print("\n🔍 Validation & info:")
    print(f"   • Alice valid → {await sm.validate_session(alice)}")
    print(f"   • Bob valid   → {await sm.validate_session(bob)}")
    print(f"   • Invalid     → {await sm.validate_session('bad_id')}")

    info: Dict[str, Any] = await sm.get_session_info(alice)
    print("   • Alice info:")
    for k in ("user_id", "created_at", "expires_at", "custom_metadata"):
        print(f"     - {k}: {info[k]}")

    # ── Advanced ops
    print("\n🔧 Updating metadata & TTL…")
    await sm.update_session_metadata(alice, {"theme": "dark", "login_count": 5})
    await sm.extend_session_ttl(bob, additional_hours=12)
    print("   • Done")

    # ── Admin helpers
    print("\n📊 Admin helpers:")
    print(f"   • Cache stats → {sm.get_cache_stats()}")
    print(f"   • Cleanup expired → {await sm.cleanup_expired_sessions()}")


# ────────────────────────────────────────────────────────────────────
# 3.  Multi-sandbox (multi-tenant) demo
# ────────────────────────────────────────────────────────────────────
async def demonstrate_multi_sandbox():
    print("\n" + "=" * 70)
    print("MULTI-SANDBOX DEMONSTRATION")
    print("=" * 70)

    os.environ["SESSION_PROVIDER"] = "memory"
    app_a = SessionManager(sandbox_id="app-a")
    app_b = SessionManager(sandbox_id="app-b")
    shared = SessionManager(sandbox_id="shared-services")

    alice_a = await app_a.allocate_session(user_id="alice")
    bob_b = await app_b.allocate_session(user_id="bob")
    system_shared = await shared.allocate_session(user_id="system")

    print(f"   • app-a / alice   → {alice_a}")
    print(f"   • app-b / bob     → {bob_b}")
    print(f"   • shared / system → {system_shared}")
    print("\n✅ Same user in different sandboxes = independent sessions")


# ────────────────────────────────────────────────────────────────────
# 4.  Real-world session scenarios
# ────────────────────────────────────────────────────────────────────
async def demonstrate_real_world_scenarios():
    print("\n" + "=" * 70)
    print("REAL-WORLD SCENARIOS")
    print("=" * 70)

    os.environ["SESSION_PROVIDER"] = "memory"

    # Web app
    web = SessionManager(sandbox_id="webapp-prod", default_ttl_hours=8)
    user = await web.allocate_session(
        user_id="user123",
        custom_metadata={
            "login_method": "oauth",
            "ip": "192.0.2.10",
            "ua": "Mozilla/5.0…",
        },
    )
    await web.update_session_metadata(user, {"files_uploaded": 3})
    print(f"🌐 Web-app session → {user}")

    # MCP server
    mcp = SessionManager(sandbox_id="mcp-server", default_ttl_hours=24)
    conv = await mcp.allocate_session(
        user_id="conversation_abc",
        custom_metadata={"client": "Claude", "tools": ["file_read", "file_write"]},
    )
    print(f"🤖 MCP conversation session → {conv}")

    # API gateway
    api = SessionManager(sandbox_id="api-gateway", default_ttl_hours=1)
    for cid, tier, limit in [
        ("alpha", "premium", 1000),
        ("beta", "standard", 100),
    ]:
        sid = await api.allocate_session(
            user_id=cid, custom_metadata={"tier": tier, "rate_limit": limit}
        )
        print(f"⚡ API client {cid}: {tier} ({limit}/h) → {sid}")


# ────────────────────────────────────────────────────────────────────
# 5.  Error handling & edge cases
# ────────────────────────────────────────────────────────────────────
async def demonstrate_error_handling():
    print("\n" + "=" * 70)
    print("ERROR HANDLING & EDGE CASES")
    print("=" * 70)

    mgr = SessionManager(sandbox_id="errors")
    bad = "no_such_session"
    print("🧪 Invalid ops:")
    print(f"   • validate → {await mgr.validate_session(bad)}")
    print(f"   • info     → {await mgr.get_session_info(bad)}")
    print(f"   • update   → {await mgr.update_session_metadata(bad, {'x': 1})}")
    print(f"   • extend   → {await mgr.extend_session_ttl(bad, 1)}")
    print(f"   • delete   → {await mgr.delete_session(bad)}")

    # Expiry cleanup
    tmp = await mgr.allocate_session(ttl_hours=0.001)
    print(f"\n   • Temp session → {tmp}")
    await asyncio.sleep(4)
    print(f"   • Still valid? → {await mgr.validate_session(tmp)}")
    print(f"   • Cleaned → {await mgr.cleanup_expired_sessions()}")


# ────────────────────────────────────────────────────────────────────
# Main driver
# ────────────────────────────────────────────────────────────────────
async def main():
    print("🎯  CHUK Sessions Demonstration\n")
    try:
        await demonstrate_basic_providers()
        await demonstrate_session_manager()
        await demonstrate_multi_sandbox()
        await demonstrate_real_world_scenarios()
        await demonstrate_error_handling()

        print("\n" + "=" * 70)
        print("✅  ALL DEMOS COMPLETED SUCCESSFULLY")
        print("=" * 70)
    except Exception as exc:  # pragma: no cover
        import traceback

        print(f"\n❌  Demo failed: {exc}")
        traceback.print_exc()


if __name__ == "__main__":
    # Strip provider overrides to keep demo deterministic
    for var in ("SESSION_PROVIDER", "SESSION_REDIS_URL"):
        os.environ.pop(var, None)

    asyncio.run(main())
