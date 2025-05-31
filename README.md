# 🚀 CHUK Sessions

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](https://github.com/chrishayuk/chuk-sessions)

**Async-native session storage with TTL support and multiple backends**

CHUK Sessions provides a clean, async-first API for session management with automatic expiration, supporting both in-memory and Redis storage backends. Perfect for web applications, API servers, and microservices that need reliable session handling.

## ✨ Key Features

- **🔥 Fully Async** - Built for modern Python async/await patterns
- **⏰ TTL Support** - Automatic expiration with precise timing
- **🔄 Multiple Providers** - Memory (development) and Redis (production)
- **🛡️ Type Safe** - Full typing support with excellent IDE integration
- **🧪 Well Tested** - Comprehensive test suite with 95%+ coverage
- **📦 Zero Config** - Works out of the box, configurable via environment variables
- **🚀 Production Ready** - Used in production by CHUK MCP Runtime

## 🚀 Quick Start

### Installation

```bash
pip install chuk-sessions

# Or with Redis support
pip install chuk-sessions[redis]
```

### Basic Usage

```python
import asyncio
from chuk_sessions.provider_factory import factory_for_env

async def main():
    # Get a session factory (uses memory by default)
    session_factory = factory_for_env()
    
    # Use the session
    async with session_factory() as session:
        # Store data with 300 second TTL
        await session.setex("user:123", 300, "alice")
        
        # Retrieve data
        username = await session.get("user:123")
        print(f"User: {username}")  # User: alice
        
        # Delete when done
        await session.delete("user:123")

asyncio.run(main())
```

## 🏗️ Architecture

CHUK Sessions uses a **provider pattern** for maximum flexibility:

```
┌─────────────────┐
│  Your App       │
├─────────────────┤
│ Factory Layer   │  ← Environment-driven provider selection
├─────────────────┤
│ Provider Layer  │  ← Memory, Redis, custom providers
├─────────────────┤
│ Transport       │  ← Async I/O, connection management
└─────────────────┘
```

## 📖 Providers

### Memory Provider (Default)

Perfect for development, testing, and single-instance deployments:

```python
import os
os.environ['SESSION_PROVIDER'] = 'memory'

# Alternative names also work
os.environ['SESSION_PROVIDER'] = 'mem'
os.environ['SESSION_PROVIDER'] = 'inmemory'
```

**Features:**
- ✅ Zero dependencies
- ✅ Instant startup
- ✅ Perfect for testing
- ⚠️ Data lost on restart
- ⚠️ Single process only

### Redis Provider

Production-ready with persistence and clustering support:

```python
import os
os.environ['SESSION_PROVIDER'] = 'redis'
os.environ['SESSION_REDIS_URL'] = 'redis://localhost:6379/0'

# Alternative names
os.environ['SESSION_PROVIDER'] = 'redis_store'
```

**Features:**
- ✅ Persistent storage
- ✅ Multi-instance support
- ✅ Clustering support
- ✅ High availability
- 🔧 Requires Redis server

## 🔧 Configuration

Configure CHUK Sessions entirely via environment variables:

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `SESSION_PROVIDER` | Provider to use | `memory` | `redis` |
| `SESSION_REDIS_URL` | Redis connection URL | - | `redis://localhost:6379/0` |
| `REDIS_URL` | Fallback Redis URL | - | `redis://user:pass@host:6379/0` |
| `REDIS_TLS_INSECURE` | Allow insecure TLS | `0` | `1` |

### Redis URL Formats

```bash
# Basic
redis://localhost:6379/0

# With auth
redis://user:password@localhost:6379/0

# TLS
rediss://localhost:6380/0

# Sentinel
redis://sentinel1:26379,sentinel2:26379/mymaster

# Cluster
redis://node1:7000,node2:7000,node3:7000
```

## 💡 Usage Examples

### Web Session Management

```python
import json
from chuk_sessions.provider_factory import factory_for_env

async def create_user_session(user_id: str, username: str):
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        session_data = {
            "user_id": user_id,
            "username": username,
            "login_time": "2024-01-01T10:00:00Z",
            "permissions": ["read", "write"]
        }
        
        # Store for 30 minutes
        await session.setex(f"session:{user_id}", 1800, json.dumps(session_data))
        
        return f"session:{user_id}"

async def validate_session(session_key: str):
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        data = await session.get(session_key)
        if data:
            return json.loads(data)
        return None

async def logout_user(session_key: str):
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        await session.delete(session_key)
```

### API Rate Limiting

```python
async def check_rate_limit(api_key: str, limit: int = 100, window: int = 3600):
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        key = f"ratelimit:{api_key}"
        current = await session.get(key)
        
        if current is None:
            # First request in window
            await session.setex(key, window, "1")
            return True, 1, limit
        
        count = int(current)
        if count >= limit:
            return False, count, limit
        
        # Increment counter
        await session.setex(key, window, str(count + 1))
        return True, count + 1, limit

# Usage
allowed, current, limit = await check_rate_limit("api_key_123")
if not allowed:
    raise Exception(f"Rate limit exceeded: {current}/{limit}")
```

### Caching Layer

```python
import hashlib

async def cached_expensive_operation(params: dict):
    # Create cache key from parameters
    cache_key = "cache:" + hashlib.md5(
        json.dumps(params, sort_keys=True).encode()
    ).hexdigest()
    
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        # Check cache first
        cached = await session.get(cache_key)
        if cached:
            return json.loads(cached)
        
        # Perform expensive operation
        result = await some_expensive_computation(params)
        
        # Cache for 1 hour
        await session.setex(cache_key, 3600, json.dumps(result))
        
        return result
```

### Temporary Tokens

```python
import secrets

async def create_verification_code(user_id: str):
    code = secrets.token_urlsafe(8)
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        # Store code for 10 minutes
        await session.setex(f"verify:{user_id}", 600, code)
        
    return code

async def verify_code(user_id: str, provided_code: str):
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        stored_code = await session.get(f"verify:{user_id}")
        
        if stored_code and stored_code == provided_code:
            # Delete code after successful verification
            await session.delete(f"verify:{user_id}")
            return True
        
        return False
```

## 🧪 Testing

CHUK Sessions is perfect for testing because it supports in-memory storage:

```python
import pytest
from chuk_sessions.provider_factory import factory_for_env

@pytest.fixture
async def session():
    """Provide a clean session for each test."""
    import os
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    session_factory = factory_for_env()
    async with session_factory() as session:
        yield session

@pytest.mark.asyncio
async def test_session_storage(session):
    await session.setex("test_key", 60, "test_value")
    result = await session.get("test_key")
    assert result == "test_value"

@pytest.mark.asyncio
async def test_ttl_expiration(session):
    await session.setex("short_lived", 1, "value")
    
    # Should exist immediately
    assert await session.get("short_lived") == "value"
    
    # Should expire after TTL
    import asyncio
    await asyncio.sleep(1.1)
    assert await session.get("short_lived") is None
```

## 🚀 Production Deployment

### Docker Compose Example

```yaml
version: '3.8'

services:
  app:
    build: .
    environment:
      - SESSION_PROVIDER=redis
      - SESSION_REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis
    
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"

volumes:
  redis_data:
```

### Kubernetes Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: app
        image: myapp:latest
        env:
        - name: SESSION_PROVIDER
          value: "redis"
        - name: SESSION_REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: url
```

## 🛡️ Best Practices

### Security

```python
# ✅ Use appropriate TTLs
await session.setex("session:user", 1800, data)  # 30 minutes
await session.setex("temp_token", 300, token)    # 5 minutes

# ✅ Clean up sensitive data
await session.delete("password_reset_token")

# ✅ Use namespaced keys
session_key = f"app:session:{user_id}"
cache_key = f"app:cache:{operation_id}"
```

### Performance

```python
# ✅ Batch operations when possible
async with session_factory() as session:
    await session.setex("key1", 60, "value1")
    await session.setex("key2", 60, "value2")
    await session.setex("key3", 60, "value3")

# ✅ Use appropriate TTLs
short_lived = 300    # 5 minutes for temp data
medium_lived = 3600  # 1 hour for cache
long_lived = 86400   # 24 hours for sessions
```

### Error Handling

```python
async def robust_session_operation():
    session_factory = factory_for_env()
    
    try:
        async with session_factory() as session:
            return await session.get("key")
    except Exception as e:
        logger.error(f"Session operation failed: {e}")
        return None  # Graceful degradation
```

## 🔧 Advanced Usage

### Custom Provider

Create your own provider by implementing the session interface:

```python
# custom_provider.py
from contextlib import asynccontextmanager

class CustomSession:
    async def setex(self, key: str, ttl: int, value: str):
        # Your implementation
        pass
    
    async def get(self, key: str):
        # Your implementation
        pass
    
    async def delete(self, key: str):
        # Your implementation
        pass
    
    async def close(self):
        # Cleanup
        pass

def factory():
    @asynccontextmanager
    async def _ctx():
        session = CustomSession()
        try:
            yield session
        finally:
            await session.close()
    
    return _ctx
```

### Environment-Specific Configuration

```python
# config.py
import os

def configure_sessions():
    env = os.getenv('ENVIRONMENT', 'development')
    
    if env == 'development':
        os.environ['SESSION_PROVIDER'] = 'memory'
    elif env == 'testing':
        os.environ['SESSION_PROVIDER'] = 'memory'
    elif env == 'production':
        os.environ['SESSION_PROVIDER'] = 'redis'
        os.environ['SESSION_REDIS_URL'] = os.getenv('REDIS_URL')
```

## 📊 Performance

CHUK Sessions delivers excellent performance across both providers. Here are verified benchmarks from real testing:

### Verified Benchmarks

| Provider | Operation | Avg Latency | Throughput | Notes |
|----------|-----------|-------------|------------|-------|
| Memory | GET | 0.001ms | 1,415k ops/sec | In-process, zero network overhead |
| Memory | SET | 0.001ms | 682k ops/sec | Direct memory access |
| Redis (local) | GET | 0.047ms | 21k ops/sec | Local Redis instance |
| Redis (local) | SET | 0.066ms | 15k ops/sec | Includes persistence overhead |

*Benchmarks on MacBook Pro M3 Max (16 cores, 128GB RAM), Python 3.11, local Redis*

### Performance Characteristics

**Memory Provider:**
- 🚀 **Ultra-fast**: Sub-millisecond operations
- 💾 **Memory efficient**: ~200-300 bytes per item
- 🔧 **Zero setup**: No external dependencies
- ⚠️ **Volatile**: Data lost on restart

**Redis Provider:**
- 🏛️ **Persistent**: Survives application restarts
- 🌐 **Scalable**: Supports clustering and replication
- 📊 **Consistent**: ~0.05ms average latency
- 🔄 **Concurrent**: Excellent multi-session performance

### Concurrent Access Performance

| Provider | Concurrent Sessions | Throughput | P95 Latency |
|----------|-------------------|------------|-------------|
| Memory | 5 | 573k ops/sec | 0.002ms |
| Redis | 5 | 16k ops/sec | 0.346ms |

### Large Data Handling

Both providers handle large payloads efficiently:

- **10KB values**: Memory ~0.001ms, Redis ~0.09ms
- **JSON objects**: Excellent performance for structured data
- **Memory scaling**: Linear growth with item count

### Running Your Own Benchmarks

Get performance data for your specific environment:

```bash
# Install performance testing dependencies
pip install psutil

# Run comprehensive benchmarks
python performance_test.py
```

The test suite provides:
- Operations per second metrics
- Latency distribution (avg, median, P95)
- Memory usage analysis
- Concurrent access patterns
- Large value performance

### Performance Optimization Tips

```python
# ✅ Batch operations when possible
async with session_factory() as session:
    tasks = [
        session.setex(f"key_{i}", 60, f"value_{i}")
        for i in range(100)
    ]
    await asyncio.gather(*tasks)

# ✅ Use appropriate connection pooling for Redis
os.environ['SESSION_REDIS_URL'] = 'redis://localhost:6379/0?max_connections=20'

# ✅ Choose TTLs based on access patterns
short_lived = 300    # 5 minutes for temp data
medium_lived = 3600  # 1 hour for cache
long_lived = 86400   # 24 hours for sessions

# ✅ Consider data size for provider choice
if need_persistence:
    provider = "redis"  # Persistent, good performance
else:
    provider = "memory"  # Ultra-fast, development/testing
```

### When to Use Each Provider

**Choose Memory When:**
- 🧪 Development and testing
- 🚀 Maximum performance needed
- 💻 Single-instance deployment
- 🔄 Data volatility is acceptable

**Choose Redis When:**
- 🏭 Production deployment
- 💾 Data persistence required
- 🌐 Multi-instance scaling
- 🔒 High availability needed

## 🤝 Contributing

We welcome contributions! Here's how to get started:

```bash
# Clone the repository
git clone https://github.com/chrishayuk/chuk-sessions.git
cd chuk-sessions

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=chuk_sessions

# Run linting
flake8 chuk_sessions tests
black chuk_sessions tests
mypy chuk_sessions
```

### Development Setup

```bash
# Install Redis for integration tests
brew install redis  # macOS
sudo apt install redis-server  # Ubuntu

# Start Redis
redis-server

# Run all tests including Redis integration
pytest --redis
```

## 📝 Changelog

### v1.0.0 (2024-01-01)
- ✨ Initial release
- 🚀 Memory and Redis providers
- ⏰ TTL support
- 🧪 Comprehensive test suite
- 📖 Full documentation

### v0.9.0 (2023-12-15)
- 🧪 Beta release
- 🔧 Provider architecture
- 📊 Performance optimizations

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Documentation**: [https://chuk-sessions.readthedocs.io](https://chuk-sessions.readthedocs.io)
- **PyPI**: [https://pypi.org/project/chuk-sessions/](https://pypi.org/project/chuk-sessions/)
- **Source Code**: [https://github.com/chrishayuk/chuk-sessions](https://github.com/chrishayuk/chuk-sessions)
- **Issue Tracker**: [https://github.com/chrishayuk/chuk-sessions/issues](https://github.com/chrishayuk/chuk-sessions/issues)

## 🙏 Acknowledgments

- Built for the [CHUK MCP Runtime](https://github.com/chrishayuk/chuk-mcp-runtime) project
- Inspired by Redis and Memcached
- Thanks to all contributors and users

---

**Made with ❤️ for the async Python community**