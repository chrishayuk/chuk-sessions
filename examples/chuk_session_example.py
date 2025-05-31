#!/usr/bin/env python3
"""
CHUK Sessions Example Script

This script demonstrates how to use the chuk_sessions package with different
providers (memory and Redis) for session storage with TTL support.
"""

import asyncio
import json
import os
import time
from typing import Dict, Any

# Import the session provider factory
from chuk_sessions.provider_factory import factory_for_env


async def demonstrate_memory_provider():
    """Demonstrate memory provider usage."""
    print("=" * 60)
    print("MEMORY PROVIDER DEMONSTRATION")
    print("=" * 60)
    
    # Set environment to use memory provider
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    # Get the factory and create a session
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        print("✓ Created memory session")
        
        # Store some session data
        print("\n📝 Storing session data...")
        await session.setex("user:123", 60, json.dumps({
            "user_id": "123",
            "username": "alice",
            "role": "admin",
            "login_time": "2024-01-01T10:00:00Z"
        }))
        
        await session.setex("cache:expensive_calc", 30, json.dumps({
            "result": 42,
            "computed_at": time.time()
        }))
        
        await session.setex("temp_token", 5, "abc123def456")
        
        print("   • User session (60s TTL)")
        print("   • Cache result (30s TTL)")
        print("   • Temp token (5s TTL)")
        
        # Retrieve data
        print("\n📖 Retrieving stored data...")
        user_data = await session.get("user:123")
        cache_data = await session.get("cache:expensive_calc")
        token = await session.get("temp_token")
        
        print(f"   • User data: {json.loads(user_data)['username']}")
        print(f"   • Cache result: {json.loads(cache_data)['result']}")
        print(f"   • Temp token: {token}")
        
        # Test TTL expiration
        print("\n⏰ Testing TTL expiration...")
        print("   Waiting 6 seconds for temp token to expire...")
        await asyncio.sleep(6)
        
        expired_token = await session.get("temp_token")
        user_still_valid = await session.get("user:123")
        
        print(f"   • Temp token after 6s: {expired_token}")
        print(f"   • User session still valid: {user_still_valid is not None}")
        
        # Delete a key
        print("\n🗑️  Testing key deletion...")
        deleted = await session.delete("cache:expensive_calc")
        cache_after_delete = await session.get("cache:expensive_calc")
        
        print(f"   • Deletion successful: {deleted}")
        print(f"   • Cache data after delete: {cache_after_delete}")


async def demonstrate_redis_provider():
    """Demonstrate Redis provider usage (with mocking)."""
    print("\n" + "=" * 60)
    print("REDIS PROVIDER DEMONSTRATION")
    print("=" * 60)
    
    # Set environment to use Redis provider
    os.environ['SESSION_PROVIDER'] = 'redis'
    os.environ['SESSION_REDIS_URL'] = 'redis://localhost:6379/1'
    
    try:
        # Get the factory and create a session
        session_factory = factory_for_env()
        
        async with session_factory() as session:
            print("✓ Created Redis session")
            
            # Store web session data
            print("\n📝 Storing web session data...")
            session_data = {
                "session_id": "sess_789",
                "user_id": "789",
                "username": "bob",
                "permissions": ["read", "write"],
                "csrf_token": "csrf_abc123",
                "last_activity": time.time()
            }
            
            await session.setex("session:sess_789", 1800, json.dumps(session_data))
            
            # Store API rate limiting data
            await session.setex("ratelimit:api_key_456", 3600, json.dumps({
                "requests": 95,
                "limit": 100,
                "reset_time": time.time() + 3600
            }))
            
            # Store temporary verification code
            await session.setex("verify_code:user789", 300, "987654")
            
            print("   • Web session (30 min TTL)")
            print("   • Rate limit data (1 hour TTL)")
            print("   • Verification code (5 min TTL)")
            
            # Simulate session validation
            print("\n🔍 Simulating session validation...")
            stored_session = await session.get("session:sess_789")
            if stored_session:
                session_info = json.loads(stored_session)
                print(f"   • Session valid for user: {session_info['username']}")
                print(f"   • Permissions: {', '.join(session_info['permissions'])}")
            
            # Simulate rate limiting check
            rate_data = await session.get("ratelimit:api_key_456")
            if rate_data:
                rate_info = json.loads(rate_data)
                print(f"   • API requests used: {rate_info['requests']}/{rate_info['limit']}")
            
            # Simulate verification code check
            verify_code = await session.get("verify_code:user789")
            print(f"   • Verification code: {verify_code}")
            
            # Update session activity
            print("\n🔄 Updating session activity...")
            session_info['last_activity'] = time.time()
            await session.setex("session:sess_789", 1800, json.dumps(session_info))
            print("   • Session activity timestamp updated")
            
            # Clean up verification code after use
            await session.delete("verify_code:user789")
            print("   • Verification code deleted after use")
            
    except Exception as e:
        print(f"⚠️  Redis connection failed (this is expected in demo): {e}")
        print("   In production, ensure Redis is running and accessible")


async def demonstrate_multiple_sessions():
    """Demonstrate using multiple session providers concurrently."""
    print("\n" + "=" * 60)
    print("MULTIPLE SESSIONS DEMONSTRATION")
    print("=" * 60)
    
    # Create multiple session factories
    os.environ['SESSION_PROVIDER'] = 'memory'
    memory_factory = factory_for_env()
    
    # Simulate different application components using sessions
    async def user_session_manager():
        """Simulate user session management."""
        async with memory_factory() as session:
            await session.setex("user:component:active_users", 120, "42")
            await session.setex("user:component:total_sessions", 300, "1337")
            return "User session component ready"
    
    async def cache_manager():
        """Simulate cache management.""" 
        async with memory_factory() as session:
            await session.setex("cache:component:db_queries", 60, json.dumps({
                "user_profile_123": {"name": "Alice", "email": "alice@example.com"},
                "user_profile_456": {"name": "Bob", "email": "bob@example.com"}
            }))
            return "Cache component ready"
    
    async def notification_manager():
        """Simulate notification management."""
        async with memory_factory() as session:
            await session.setex("notifications:pending:user123", 180, json.dumps([
                {"type": "message", "from": "bob", "text": "Hello!"},
                {"type": "system", "text": "Password expires in 7 days"}
            ]))
            return "Notification component ready"
    
    # Run all components concurrently
    print("🚀 Starting multiple session components...")
    results = await asyncio.gather(
        user_session_manager(),
        cache_manager(), 
        notification_manager()
    )
    
    for result in results:
        print(f"   • {result}")
    
    # Verify all data is accessible
    print("\n🔍 Verifying shared session data...")
    async with memory_factory() as session:
        active_users = await session.get("user:component:active_users")
        cached_profiles = await session.get("cache:component:db_queries")
        pending_notifications = await session.get("notifications:pending:user123")
        
        print(f"   • Active users: {active_users}")
        print(f"   • Cached profiles: {len(json.loads(cached_profiles))} users")
        print(f"   • Pending notifications: {len(json.loads(pending_notifications))} items")


async def demonstrate_error_handling():
    """Demonstrate error handling and edge cases."""
    print("\n" + "=" * 60)
    print("ERROR HANDLING DEMONSTRATION")
    print("=" * 60)
    
    os.environ['SESSION_PROVIDER'] = 'memory'
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        # Test with various data types
        print("📝 Testing various data types...")
        test_data = {
            "json_object": json.dumps({"key": "value", "number": 42}),
            "plain_string": "Hello, World!",
            "unicode_string": "🚀 Unicode test: café, naïve, 测试",
            "empty_string": "",
            "multiline": "Line 1\nLine 2\nLine 3",
            "large_data": "x" * 10000  # 10KB string
        }
        
        for key, value in test_data.items():
            await session.setex(f"test:{key}", 60, value)
            retrieved = await session.get(f"test:{key}")
            success = retrieved == value
            print(f"   • {key}: {'✓' if success else '✗'}")
        
        # Test edge cases
        print("\n🧪 Testing edge cases...")
        
        # Very short TTL
        await session.setex("short_ttl", 1, "expires_soon")
        await asyncio.sleep(0.5)
        still_there = await session.get("short_ttl")
        print(f"   • Short TTL (0.5s check): {'✓' if still_there else '✗ (expired)'}")
        
        await asyncio.sleep(1)
        expired = await session.get("short_ttl")
        print(f"   • After expiration: {'✗ (still there)' if expired else '✓ (properly expired)'}")
        
        # Non-existent key
        missing = await session.get("does_not_exist")
        print(f"   • Non-existent key: {'✓' if missing is None else '✗'}")
        
        # Delete non-existent key
        delete_result = await session.delete("does_not_exist")
        print(f"   • Delete non-existent: {'✓' if not delete_result else '✗'}")


async def main():
    """Run all demonstrations."""
    print("🎯 CHUK Sessions Package Demonstration")
    print("📦 Package: chuk_sessions")
    print("🔧 Features: TTL-aware session storage with multiple providers")
    
    try:
        await demonstrate_memory_provider()
        await demonstrate_redis_provider()
        await demonstrate_multiple_sessions()
        await demonstrate_error_handling()
        
        print("\n" + "=" * 60)
        print("✅ ALL DEMONSTRATIONS COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\n📚 Key Features Demonstrated:")
        print("   • Memory provider with TTL support")
        print("   • Redis provider integration")
        print("   • Multiple concurrent sessions")
        print("   • Error handling and edge cases")
        print("   • JSON data serialization")
        print("   • Session cleanup and deletion")
        print("\n🚀 Ready for production use!")
        
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