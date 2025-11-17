#!/usr/bin/env python3
import asyncio
from chuk_sessions import get_session


async def main():
    async with get_session() as session:
        # Set with default TTL (1 hour or SESSION_DEFAULT_TTL)
        await session.set("user:123", "Alice")
        await session.set("config", "settings")

        # Set with explicit TTL
        await session.setex("token:xyz", 60, "secret123")  # 1 minute
        await session.setex("cache:result", 300, "computed")  # 5 minutes

        # Get items
        user = await session.get("user:123")
        token = await session.get("token:xyz")
        missing = await session.get("nonexistent")

        print(f"User: {user}")  # User: Alice
        print(f"Token: {token}")  # Token: secret123
        print(f"Missing: {missing}")  # Missing: None


asyncio.run(main())
