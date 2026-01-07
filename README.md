# CHUK Sessions

**Simple, fast async session management for Python**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-202%20passing-brightgreen.svg)](https://github.com/chrishayuk/chuk-sessions)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg)](https://github.com/chrishayuk/chuk-sessions)

Dead simple session management with automatic expiration, multiple storage backends, and multi-tenant isolation. Perfect for web apps, APIs, and any system needing reliable sessions.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                        │
└─────────────────────────────────┬───────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │   Convenience API Layer   │
                    │  get_session() / session  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │     SessionManager        │
                    │  • Lifecycle Management   │
                    │  • TTL & Expiration       │
                    │  • Metadata & Validation  │
                    │  • Multi-tenant Isolation │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │    Provider Factory       │
                    │  Auto-detect from env     │
                    └─────────────┬─────────────┘
                                  │
                ┌─────────────────┴─────────────────┐
                │                                   │
    ┌───────────▼──────────┐          ┌───────────▼──────────┐
    │  Memory Provider     │          │   Redis Provider     │
    │  • In-process cache  │          │  • Persistent store  │
    │  • 1.3M ops/sec      │          │  • Distributed       │
    │  • Dev/Testing       │          │  • Production        │
    └──────────────────────┘          └──────────────────────┘

Features:
  ✓ Pydantic models with validation    ✓ Type-safe enums (no magic strings)
  ✓ Automatic TTL expiration            ✓ Multi-sandbox isolation
  ✓ CSRF protection utilities           ✓ Cryptographic session IDs
  ✓ 202 tests, 90% coverage             ✓ Production-ready
```

## 🚀 Quick Start

```bash
# Basic installation (memory provider only)
pip install chuk-sessions

# With Redis support
pip install chuk-sessions[redis]

# Full installation with all optional dependencies
pip install chuk-sessions[all]

# Development installation
pip install chuk-sessions[dev]
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

## 📖 How It Works

```
Session Lifecycle:
┌─────────────┐
│ 1. Create   │  mgr.allocate_session(user_id="alice")
└──────┬──────┘
       │ ← Returns session_id: "sess-alice-1234..."
       ▼
┌─────────────┐
│ 2. Validate │  mgr.validate_session(session_id)
└──────┬──────┘
       │ ← Returns: True (session exists & not expired)
       ▼
┌─────────────┐
│ 3. Use      │  mgr.get_session_info(session_id)
└──────┬──────┘  mgr.update_session_metadata(...)
       │ ← Access/modify session data
       ▼
┌─────────────┐
│ 4. Extend   │  mgr.extend_session_ttl(session_id, hours=2)
└──────┬──────┘  (optional - keep session alive)
       │
       ▼
┌─────────────┐
│ 5. Expire   │  Automatic after TTL
└──────┬──────┘  or mgr.delete_session(session_id)
       │
       ▼
    [Done]
```

## ✨ What's New in v0.5

- **🎯 Pydantic Native**: All models are Pydantic-based with automatic validation
- **🔒 Type-Safe Enums**: No more magic strings - `SessionStatus.ACTIVE`, `ProviderType.REDIS`
- **📦 Exported Types**: Full IDE autocomplete for `SessionMetadata`, `CSRFTokenInfo`, etc.
- **⚡ Async Native**: Built from ground-up for async/await
- **🔄 Backward Compatible**: Existing code works unchanged
- **✅ 90%+ Test Coverage**: 202 tests, production-ready

```python
from chuk_sessions import SessionManager, SessionStatus, SessionMetadata

# Type-safe with IDE autocomplete
mgr = SessionManager(sandbox_id="my-app")
session_id = await mgr.allocate_session()

# Pydantic models with validation
info: dict = await mgr.get_session_info(session_id)
metadata = SessionMetadata(**info)
print(metadata.status)  # SessionStatus.ACTIVE
```

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
# Development - blazing fast in-memory (default)
export SESSION_PROVIDER=memory

# Production - persistent Redis standalone (requires chuk-sessions[redis])
export SESSION_PROVIDER=redis
export SESSION_REDIS_URL=redis://localhost:6379/0

# Production - Redis Cluster with automatic detection
export SESSION_PROVIDER=redis
export SESSION_REDIS_URL=redis://node1:7000,node2:7001,node3:7002
```

### 📊 **Performance** (Real Benchmarks)

Actual performance from `examples/performance_test.py`:

| Provider | Operation | Throughput | Avg Latency | P95 Latency |
|----------|-----------|------------|-------------|-------------|
| Memory | GET | 1,312,481 ops/sec | 0.001ms | 0.001ms |
| Memory | SET | 1,141,011 ops/sec | 0.001ms | 0.001ms |
| Memory | DELETE | 1,481,848 ops/sec | 0.001ms | 0.001ms |
| Redis | GET | ~20K ops/sec | 0.05ms | 0.08ms |
| Redis | SET | ~18K ops/sec | 0.06ms | 0.09ms |

**Concurrent Access** (5 sessions, 500 ops):
- Overall Throughput: 406,642 ops/sec
- Average Latency: 0.002ms

## 💡 Real-World Use Cases

Based on `examples/chuk_session_example.py`:

### 🌐 Web App Sessions
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
export SESSION_PROVIDER=memory          # Default - no extra dependencies
export SESSION_PROVIDER=redis           # Requires: pip install chuk-sessions[redis]

# TTL settings
export SESSION_DEFAULT_TTL=3600         # 1 hour default

# Redis config (if using redis provider)
# Standalone Redis
export SESSION_REDIS_URL=redis://localhost:6379/0

# Redis Cluster (comma-separated hosts - automatically detected)
export SESSION_REDIS_URL=redis://node1:7000,node2:7001,node3:7002

# Redis with TLS
export SESSION_REDIS_URL=rediss://localhost:6380/0
export REDIS_TLS_INSECURE=1             # Set to 1 to skip certificate verification (dev only)
```

## 📦 Installation Options

| Command | Includes | Use Case |
|---------|----------|----------|
| `pip install chuk-sessions` | Memory provider only | Development, testing, lightweight apps |
| `pip install chuk-sessions[redis]` | + Redis support | Production apps with Redis |
| `pip install chuk-sessions[all]` | All optional features | Maximum compatibility |
| `pip install chuk-sessions[dev]` | Development tools | Contributing, testing |

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

## 🎪 Examples & Demos

All examples are tested and working! Run them to see CHUK Sessions in action:

### 🚀 Getting Started
```bash
# Simple 3-line example - perfect first step
python examples/simple_example.py

# Interactive tutorial with explanations
python examples/quickstart.py
```

**Output:**
```
User: Alice
Token: secret123
Missing: None
```

### 🔧 Comprehensive Demo
```bash
# Complete feature demonstration
python examples/chuk_session_example.py
```

**Shows:**
- ✓ Low-level provider usage (memory/redis)
- ✓ High-level SessionManager API
- ✓ Multi-sandbox isolation (multi-tenant)
- ✓ Real-world scenarios (web app, MCP server, API gateway)
- ✓ Error handling & admin helpers

### 📊 Performance Testing
```bash
# Benchmark your system
python examples/performance_test.py
```

**Output includes:**
- Throughput measurements (1.3M+ ops/sec)
- Latency percentiles (P50, P95, P99)
- Memory usage analysis
- Concurrent access tests
- README-ready performance tables

### 🔐 Security Demos
```bash
# CSRF protection examples
python examples/csrf_demo.py

# Secure session ID generation
python examples/session_id_demo.py
```

**Features demonstrated:**
- HMAC-based CSRF tokens
- Double-submit cookie pattern
- Encrypted stateless tokens
- Cryptographic session IDs with entropy analysis
- Protocol-specific formats (MCP, HTTP, WebSocket, JWT)

## 🏗️ Why CHUK Sessions?

- **Simple**: One import, one line to start storing sessions
- **Fast**: 1.8M ops/sec in memory, 20K ops/sec with Redis
- **Reliable**: Automatic TTL, proper error handling, production-tested
- **Flexible**: Works for simple key-value storage or complex session management
- **Isolated**: Multi-tenant by design with sandbox separation
- **Optional Dependencies**: Install only what you need

Perfect for web frameworks, API servers, MCP implementations, or any Python app needing sessions.

## 🛠️ Development

```bash
# Clone and install dependencies
git clone https://github.com/chrishayuk/chuk-sessions.git
cd chuk-sessions
make dev-install

# Run tests
make test

# Run tests with coverage (90%+ coverage)
make test-cov

# Run all checks (lint, typecheck, security, tests)
make check

# Format code
make format

# Build package
make build
```

### 🚀 Release Process

```bash
# Bump version
make bump-patch  # 0.5 → 0.6
make bump-minor  # 0.5 → 1.0
make bump-major  # 0.5 → 1.0.0

# Create release (triggers GitHub Actions → PyPI)
make publish
```

### Available Makefile Commands

- `make test` - Run tests
- `make test-cov` - Run tests with coverage report
- `make lint` - Run code linters (ruff)
- `make format` - Auto-format code
- `make typecheck` - Run type checking (mypy)
- `make security` - Run security checks (bandit)
- `make check` - Run all checks
- `make clean` - Clean build artifacts
- `make build` - Build distribution packages
- `make publish` - Create tag and trigger automated release

See `make help` for all available commands.

## 📄 License

MIT License