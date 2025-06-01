#!/usr/bin/env python3
"""
CHUK Sessions Example Script

This script demonstrates how to use the enhanced chuk_sessions package with
session management, grid architecture, and different providers.
"""

import asyncio
import json
import os
import time
from typing import Dict, Any

# Import both the provider factory and the session manager
from chuk_sessions.provider_factory import factory_for_env
from chuk_sessions.session_manager import SessionManager


async def demonstrate_basic_providers():
    """Demonstrate basic provider usage (lower-level API)."""
    print("=" * 70)
    print("BASIC PROVIDER DEMONSTRATION (Lower-Level API)")
    print("=" * 70)
    
    # Set environment to use memory provider
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    # Get the factory and create a session
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        print("✓ Created memory session provider")
        
        # Store some basic session data
        print("\n📝 Storing basic session data...")
        await session.setex("user:123", 60, json.dumps({
            "user_id": "123",
            "username": "alice",
            "role": "admin",
            "login_time": "2024-01-01T10:00:00Z"
        }))
        
        await session.setex("temp_token", 5, "abc123def456")
        
        print("   • User session (60s TTL)")
        print("   • Temp token (5s TTL)")
        
        # Retrieve data
        print("\n📖 Retrieving stored data...")
        user_data = await session.get("user:123")
        token = await session.get("temp_token")
        
        print(f"   • User data: {json.loads(user_data)['username']}")
        print(f"   • Temp token: {token}")
        
        # Test TTL expiration
        print("\n⏰ Testing TTL expiration...")
        print("   Waiting 6 seconds for temp token to expire...")
        await asyncio.sleep(6)
        
        expired_token = await session.get("temp_token")
        user_still_valid = await session.get("user:123")
        
        print(f"   • Temp token after 6s: {expired_token}")
        print(f"   • User session still valid: {user_still_valid is not None}")


async def demonstrate_session_manager():
    """Demonstrate the enhanced SessionManager."""
    print("\n" + "=" * 70)
    print("SESSION MANAGER DEMONSTRATION (High-Level API)")
    print("=" * 70)
    
    # Set environment for session provider
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    # Create session manager for a sandbox
    session_mgr = SessionManager(
        sandbox_id="demo-app",
        default_ttl_hours=24
    )
    
    print("✓ Created SessionManager for sandbox: demo-app")
    
    # ═════════════════════════════════════════════════════════════════
    # Session Lifecycle Management
    # ═════════════════════════════════════════════════════════════════
    
    print("\n📝 Session Lifecycle Management...")
    
    # Create sessions for different users
    alice_session = await session_mgr.allocate_session(
        user_id="alice", 
        ttl_hours=2,
        custom_metadata={"role": "admin", "department": "engineering"}
    )
    print(f"   • Alice's session: {alice_session}")
    
    bob_session = await session_mgr.allocate_session(
        user_id="bob",
        custom_metadata={"role": "user", "department": "marketing"}
    )
    print(f"   • Bob's session: {bob_session}")
    
    # Auto-allocated session (no user_id)
    anon_session = await session_mgr.allocate_session()
    print(f"   • Anonymous session: {anon_session}")
    
    # ═════════════════════════════════════════════════════════════════
    # Session Validation and Info
    # ═════════════════════════════════════════════════════════════════
    
    print("\n🔍 Session Validation and Information...")
    
    # Validate sessions
    alice_valid = await session_mgr.validate_session(alice_session)
    bob_valid = await session_mgr.validate_session(bob_session)
    invalid_valid = await session_mgr.validate_session("invalid_session_id")
    
    print(f"   • Alice session valid: {alice_valid}")
    print(f"   • Bob session valid: {bob_valid}")
    print(f"   • Invalid session valid: {invalid_valid}")
    
    # Get session information
    alice_info = await session_mgr.get_session_info(alice_session)
    print(f"\n   • Alice's session info:")
    print(f"     - User ID: {alice_info['user_id']}")
    print(f"     - Created: {alice_info['created_at']}")
    print(f"     - Expires: {alice_info['expires_at']}")
    print(f"     - Status: {alice_info['status']}")
    print(f"     - Custom data: {alice_info['custom_metadata']}")
    
    # ═════════════════════════════════════════════════════════════════
    # Grid Architecture Support
    # ═════════════════════════════════════════════════════════════════
    
    print("\n🏗️  Grid Architecture Support...")
    
    # Generate grid paths
    alice_prefix = session_mgr.get_canonical_prefix(alice_session)
    bob_prefix = session_mgr.get_canonical_prefix(bob_session)
    
    print(f"   • Alice's grid prefix: {alice_prefix}")
    print(f"   • Bob's grid prefix: {bob_prefix}")
    
    # Generate artifact keys
    artifact_ids = ["doc123", "image456", "video789"]
    
    print(f"\n   • Alice's artifact keys:")
    for artifact_id in artifact_ids:
        key = session_mgr.generate_artifact_key(alice_session, artifact_id)
        print(f"     - {artifact_id}: {key}")
    
    print(f"\n   • Bob's artifact keys:")
    for artifact_id in artifact_ids:
        key = session_mgr.generate_artifact_key(bob_session, artifact_id)
        print(f"     - {artifact_id}: {key}")
    
    # Parse grid keys back
    sample_key = session_mgr.generate_artifact_key(alice_session, "doc123")
    parsed = session_mgr.parse_grid_key(sample_key)
    print(f"\n   • Parsed grid key '{sample_key}':")
    print(f"     - Sandbox: {parsed['sandbox_id']}")
    print(f"     - Session: {parsed['session_id']}")
    print(f"     - Artifact: {parsed['artifact_id']}")
    
    # ═════════════════════════════════════════════════════════════════
    # Advanced Session Operations
    # ═════════════════════════════════════════════════════════════════
    
    print("\n🔧 Advanced Session Operations...")
    
    # Update custom metadata
    await session_mgr.update_session_metadata(
        alice_session,
        {
            "last_login": time.time(),
            "login_count": 5,
            "preferred_theme": "dark"
        }
    )
    print("   • Updated Alice's custom metadata")
    
    # Extend session TTL
    extended = await session_mgr.extend_session_ttl(bob_session, additional_hours=12)
    print(f"   • Extended Bob's session TTL: {extended}")
    
    # Get updated session info
    alice_updated = await session_mgr.get_session_info(alice_session)
    print(f"   • Alice's updated custom metadata: {alice_updated['custom_metadata']}")
    
    # ═════════════════════════════════════════════════════════════════
    # Administrative Operations
    # ═════════════════════════════════════════════════════════════════
    
    print("\n📊 Administrative Operations...")
    
    # Get cache statistics
    stats = session_mgr.get_cache_stats()
    print(f"   • Cache stats: {stats}")
    
    # Clean up expired sessions
    cleaned = await session_mgr.cleanup_expired_sessions()
    print(f"   • Cleaned expired sessions: {cleaned}")
    
    # Session prefix pattern for discovery
    prefix_pattern = session_mgr.get_session_prefix_pattern()
    print(f"   • Session prefix pattern: {prefix_pattern}")


async def demonstrate_multi_sandbox():
    """Demonstrate multiple sandboxes (multi-tenant scenario)."""
    print("\n" + "=" * 70)
    print("MULTI-SANDBOX DEMONSTRATION (Multi-Tenant)")
    print("=" * 70)
    
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    # Create session managers for different sandboxes (tenants)
    app_a_mgr = SessionManager(sandbox_id="app-a")
    app_b_mgr = SessionManager(sandbox_id="app-b")
    shared_mgr = SessionManager(sandbox_id="shared-services")
    
    print("✓ Created session managers for multiple sandboxes")
    
    # Create sessions in different sandboxes
    print("\n📝 Creating sessions across sandboxes...")
    
    # App A sessions
    app_a_user1 = await app_a_mgr.allocate_session(
        user_id="alice", 
        custom_metadata={"app": "app-a", "role": "admin"}
    )
    app_a_user2 = await app_a_mgr.allocate_session(
        user_id="charlie",
        custom_metadata={"app": "app-a", "role": "user"}
    )
    
    # App B sessions  
    app_b_user1 = await app_b_mgr.allocate_session(
        user_id="bob",
        custom_metadata={"app": "app-b", "role": "admin"}
    )
    
    # Shared services session
    shared_session = await shared_mgr.allocate_session(
        user_id="system",
        custom_metadata={"service": "notification", "role": "system"}
    )
    
    print(f"   • App A - Alice: {app_a_user1}")
    print(f"   • App A - Charlie: {app_a_user2}")
    print(f"   • App B - Bob: {app_b_user1}")
    print(f"   • Shared - System: {shared_session}")
    
    # Show grid path isolation
    print("\n🏗️  Grid Path Isolation...")
    
    artifact_id = "document123"
    
    app_a_alice_key = app_a_mgr.generate_artifact_key(app_a_user1, artifact_id)
    app_a_charlie_key = app_a_mgr.generate_artifact_key(app_a_user2, artifact_id)
    app_b_bob_key = app_b_mgr.generate_artifact_key(app_b_user1, artifact_id)
    shared_key = shared_mgr.generate_artifact_key(shared_session, artifact_id)
    
    print(f"   • App A (Alice): {app_a_alice_key}")
    print(f"   • App A (Charlie): {app_a_charlie_key}")
    print(f"   • App B (Bob): {app_b_bob_key}")
    print(f"   • Shared Services: {shared_key}")
    
    print("\n✅ Each sandbox has isolated grid paths")
    print("✅ Same user in different sandboxes = different sessions")
    print("✅ Perfect for multi-tenant applications")


async def demonstrate_real_world_scenarios():
    """Demonstrate real-world usage scenarios."""
    print("\n" + "=" * 70)
    print("REAL-WORLD SCENARIOS DEMONSTRATION")
    print("=" * 70)
    
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    # ═════════════════════════════════════════════════════════════════
    # Scenario 1: Web Application Session Management
    # ═════════════════════════════════════════════════════════════════
    
    print("🌐 Scenario 1: Web Application Session Management")
    
    web_app_mgr = SessionManager(
        sandbox_id="webapp-prod",
        default_ttl_hours=8  # 8-hour work day sessions
    )
    
    # User login
    user_session = await web_app_mgr.allocate_session(
        user_id="user123",
        custom_metadata={
            "login_method": "oauth",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0...",
            "permissions": ["read", "write", "upload"]
        }
    )
    
    print(f"   • User login session: {user_session}")
    
    # Simulate user activity (file uploads)
    artifact_keys = []
    for i in range(3):
        artifact_id = f"upload_{i}_{int(time.time())}"
        key = web_app_mgr.generate_artifact_key(user_session, artifact_id)
        artifact_keys.append(key)
    
    print(f"   • Generated {len(artifact_keys)} artifact keys")
    
    # Update session with activity
    await web_app_mgr.update_session_metadata(
        user_session,
        {
            "last_activity": time.time(),
            "files_uploaded": len(artifact_keys),
            "session_duration_minutes": 45
        }
    )
    
    session_info = await web_app_mgr.get_session_info(user_session)
    print(f"   • Session activity: {session_info['custom_metadata']['files_uploaded']} files uploaded")
    
    # ═════════════════════════════════════════════════════════════════
    # Scenario 2: MCP Server Integration
    # ═════════════════════════════════════════════════════════════════
    
    print("\n🤖 Scenario 2: MCP Server Integration")
    
    mcp_mgr = SessionManager(
        sandbox_id="mcp-server",
        default_ttl_hours=24
    )
    
    # Claude conversation session
    claude_session = await mcp_mgr.allocate_session(
        user_id="claude_conversation",
        custom_metadata={
            "client": "claude",
            "conversation_id": "conv_abc123",
            "tools_enabled": ["file_read", "file_write", "file_list"],
            "safety_level": "standard"
        }
    )
    
    print(f"   • Claude session: {claude_session}")
    
    # Generate keys for MCP tools
    mcp_operations = [
        ("read_document", "doc_analysis_1"),
        ("write_report", "report_2024_q1"),
        ("upload_image", "diagram_flowchart"),
        ("create_summary", "meeting_notes_jan")
    ]
    
    print("   • MCP tool operations:")
    for operation, artifact_id in mcp_operations:
        key = mcp_mgr.generate_artifact_key(claude_session, artifact_id)
        print(f"     - {operation}: {key}")
    
    # ═════════════════════════════════════════════════════════════════
    # Scenario 3: API Rate Limiting & Caching
    # ═════════════════════════════════════════════════════════════════
    
    print("\n⚡ Scenario 3: API Rate Limiting & Caching")
    
    api_mgr = SessionManager(
        sandbox_id="api-gateway",
        default_ttl_hours=1  # Short-lived for rate limiting
    )
    
    # API client sessions
    api_sessions = []
    for client_id in ["client_alpha", "client_beta", "client_gamma"]:
        session = await api_mgr.allocate_session(
            user_id=client_id,
            ttl_hours=1,
            custom_metadata={
                "api_tier": "premium" if client_id == "client_alpha" else "standard",
                "rate_limit": 1000 if client_id == "client_alpha" else 100,
                "requests_made": 0
            }
        )
        api_sessions.append((client_id, session))
    
    for client_id, session in api_sessions:
        info = await api_mgr.get_session_info(session)
        tier = info['custom_metadata']['api_tier']
        limit = info['custom_metadata']['rate_limit']
        print(f"   • {client_id}: {tier} tier, {limit} requests/hour")


async def demonstrate_error_handling():
    """Demonstrate error handling and edge cases."""
    print("\n" + "=" * 70)
    print("ERROR HANDLING & EDGE CASES")
    print("=" * 70)
    
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    session_mgr = SessionManager(sandbox_id="error-test")
    
    print("🧪 Testing error conditions...")
    
    # Test invalid session operations
    invalid_session = "invalid_session_id_12345"
    
    valid = await session_mgr.validate_session(invalid_session)
    info = await session_mgr.get_session_info(invalid_session)
    updated = await session_mgr.update_session_metadata(invalid_session, {"test": "data"})
    extended = await session_mgr.extend_session_ttl(invalid_session, 1)
    deleted = await session_mgr.delete_session(invalid_session)
    
    print(f"   • Invalid session validation: {valid}")
    print(f"   • Invalid session info: {info}")
    print(f"   • Invalid session update: {updated}")
    print(f"   • Invalid session TTL extend: {extended}")
    print(f"   • Invalid session delete: {deleted}")
    
    # Test edge cases with grid keys
    print("\n🔍 Testing grid key parsing...")
    
    test_keys = [
        "grid/sandbox/session/artifact",           # Valid
        "grid/sandbox/session/artifact/subpath",   # Valid with subpath
        "invalid/path/structure",                  # Invalid
        "grid/only/two/parts",                     # Invalid
        "",                                        # Empty
        "grid/sandbox/session/"                    # Missing artifact
    ]
    
    for key in test_keys:
        parsed = session_mgr.parse_grid_key(key)
        status = "✓" if parsed else "✗"
        print(f"   • {status} '{key}': {parsed}")
    
    # Test session cleanup
    print("\n🧹 Testing session cleanup...")
    
    # Create a short-lived session for testing
    temp_session = await session_mgr.allocate_session(
        user_id="temp_user",
        ttl_hours=0.001,  # Very short TTL (3.6 seconds)
        custom_metadata={"test": "cleanup"}
    )
    
    print(f"   • Created temp session: {temp_session}")
    
    # Wait for expiration
    await asyncio.sleep(4)
    
    # Try to validate expired session
    still_valid = await session_mgr.validate_session(temp_session)
    print(f"   • Temp session valid after expiration: {still_valid}")
    
    # Cleanup expired sessions
    cleaned = await session_mgr.cleanup_expired_sessions()
    print(f"   • Cleaned up {cleaned} expired sessions")


async def main():
    """Run all demonstrations."""
    print("🎯 ENHANCED CHUK Sessions Package Demonstration")
    print("📦 Package: chuk_sessions")
    print("🔧 Features: Session management, grid architecture, multi-provider support")
    
    try:
        await demonstrate_basic_providers()
        await demonstrate_session_manager()
        await demonstrate_multi_sandbox()
        await demonstrate_real_world_scenarios()
        await demonstrate_error_handling()
        
        print("\n" + "=" * 70)
        print("✅ ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print("\n📚 Enhanced Features Demonstrated:")
        print("   • Basic provider API (memory/redis)")
        print("   • High-level SessionManager API")
        print("   • Grid architecture with path generation")
        print("   • Multi-sandbox isolation (multi-tenant)")
        print("   • Real-world scenarios (web apps, MCP, APIs)")
        print("   • Session lifecycle management")
        print("   • Custom metadata and TTL extensions")
        print("   • Comprehensive error handling")
        print("   • Administrative operations")
        print("\n🚀 Ready for production use in:")
        print("   • Web applications")
        print("   • MCP servers")  
        print("   • API gateways")
        print("   • Multi-tenant systems")
        print("   • Microservices architectures")
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Clean up environment variables at start
    for var in ['SESSION_PROVIDER', 'SESSION_REDIS_URL']:
        if var in os.environ:
            del os.environ[var]
    
    # Run the demonstration
    asyncio.run(main())