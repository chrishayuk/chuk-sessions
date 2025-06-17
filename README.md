# CHUK Sessions

**Simple, fast async session management for Python**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Dead simple session management with automatic expiration, multiple storage backends, and multi-tenant isolation. Perfect for web apps, APIs, and any system needing reliable sessions.

## 🚀 Quick Start

```bash
pip install chuk-sessions
```

```python
import asyncio
from chuk_sessions import get_session

async def main():
    async with get_session() as session:
        # Store with auto-expiration
        await session.setex("user:123", 3600, "Alice")  # 1 hour TTL
        
        # Retrieve
        user = await session.get("user:123")  # "Alice"
        
        # Automatically expires after TTL
        
asyncio.run(main())
```

That's it! Sessions automatically expire and you get instant performance.

## ⚡ Major Features

### 🎯 **Simple Storage with TTL**
```python
from chuk_sessions import get_session

async with get_session() as session:
    await session.set("key", "value")              # Default 1hr expiration
    await session.setex("temp", 60, "expires")     # Custom 60s expiration
    value = await session.get("key")               # Auto-cleanup when expired
```

### 🏢 **Multi-App Session Management**
```python
from chuk_sessions import SessionManager

# Each app gets isolated sessions
web_app = SessionManager(sandbox_id="web-portal")
api_service = SessionManager(sandbox_id="api-gateway")

# Full session lifecycle
session_id = await web_app.allocate_session(
    user_id="alice@example.com",
    custom_metadata={"role": "admin", "login_time": "2024-01-01T10:00:00Z"}
)

# Validate, extend, update
await web_app.validate_session(session_id)
await web_app.extend_session_ttl(session_id, additional_hours=2)
await web_app.update_session_metadata(session_id, {"last_activity": "now"})
```

### ⚙️ **Multiple Backends**
```bash
# Development - blazing fast in-memory
export SESSION_PROVIDER=memory

# Production - persistent Redis
export SESSION_PROVIDER=redis
export SESSION_REDIS_URL=redis://localhost:6379/0
```

### 📊 **Performance**
| Provider | Throughput | Latency |
|----------|------------|---------|
| Memory | 1.8M ops/sec | 0.00ms |
| Redis | 20K ops/sec | 0.05ms |

## 💡 Common Use Cases

### Web App Sessions
```python
web_app = SessionManager(sandbox_id="my-web-app")

# Login
session_id = await web_app.allocate_session(
    user_id="alice@example.com",
    ttl_hours=8,
    custom_metadata={"role": "admin", "theme": "dark"}
)

# Middleware validation
if not await web_app.validate_session(session_id):
    raise Unauthorized("Please log in")
```

### API Rate Limiting
```python
api = SessionManager(sandbox_id="api-gateway", default_ttl_hours=1)

session_id = await api.allocate_session(
    user_id="client_123",
    custom_metadata={"tier": "premium", "requests": 0, "limit": 1000}
)

# Check/update rate limits
info = await api.get_session_info(session_id)
requests = info['custom_metadata']['requests']
if requests >= info['custom_metadata']['limit']:
    raise RateLimitExceeded()

await api.update_session_metadata(session_id, {"requests": requests + 1})
```

### Temporary Verification Codes
```python
from chuk_sessions import get_session

async with get_session() as session:
    # Email verification code (10 minute expiry)
    await session.setex(f"verify:{email}", 600, "ABC123")
    
    # Later: verify and consume
    code = await session.get(f"verify:{email}")
    if code == user_code:
        await session.delete(f"verify:{email}")  # One-time use
        return True
```

## 🔧 Configuration

Set via environment variables:

```bash
# Provider selection
export SESSION_PROVIDER=memory          # or redis

# TTL settings
export SESSION_DEFAULT_TTL=3600         # 1 hour default

# Redis config (if using redis provider)
export SESSION_REDIS_URL=redis://localhost:6379/0
```

## 📖 API Reference

### Low-Level API
```python
from chuk_sessions import get_session

async with get_session() as session:
    await session.set(key, value)           # Store with default TTL
    await session.setex(key, ttl, value)    # Store with custom TTL (seconds)
    value = await session.get(key)          # Retrieve (None if expired)
    deleted = await session.delete(key)     # Delete (returns bool)
```

### SessionManager API
```python
from chuk_sessions import SessionManager

mgr = SessionManager(sandbox_id="my-app", default_ttl_hours=24)

# Session lifecycle
session_id = await mgr.allocate_session(user_id="alice", custom_metadata={})
is_valid = await mgr.validate_session(session_id)
info = await mgr.get_session_info(session_id)
success = await mgr.update_session_metadata(session_id, {"key": "value"})
success = await mgr.extend_session_ttl(session_id, additional_hours=2)
success = await mgr.delete_session(session_id)

# Admin helpers
stats = mgr.get_cache_stats()
cleaned = await mgr.cleanup_expired_sessions()
```

## 🎪 Examples

```bash
# Interactive quickstart
python examples/quickstart.py

# Full feature demo
python examples/chuk_session_example.py

# Performance benchmarks
python examples/performance_test.py
```

## 🏗️ Why CHUK Sessions?

- **Simple**: One import, one line to start storing sessions
- **Fast**: 1.8M ops/sec in memory, 20K ops/sec with Redis
- **Reliable**: Automatic TTL, proper error handling, production-tested
- **Flexible**: Works for simple key-value storage or complex session management
- **Isolated**: Multi-tenant by design with sandbox separation

Perfect for web frameworks, API servers, MCP implementations, or any Python app needing sessions.

## 📄 License

MIT License