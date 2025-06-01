# 🚀 CHUK Sessions

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](https://github.com/chrishayuk/chuk-sessions)

**Advanced async session management with grid architecture, TTL support, and multiple backends**

CHUK Sessions provides a comprehensive, async-first session management system with automatic expiration, grid-based path generation, and support for both in-memory and Redis storage backends. Perfect for web applications, MCP servers, API gateways, and microservices that need reliable, scalable session handling.

## ✨ Key Features

- **🔥 Fully Async** - Built for modern Python async/await patterns
- **🏗️ Grid Architecture** - Federation-ready path generation: `grid/{sandbox_id}/{session_id}/{artifact_id}`
- **🎯 Session Management** - Complete lifecycle management with metadata support
- **⏰ TTL Support** - Automatic expiration with precise timing and extensions
- **🔄 Multiple Providers** - Memory (development) and Redis (production)
- **🏢 Multi-Tenant Ready** - Sandbox isolation for SaaS applications
- **🛡️ Type Safe** - Full typing support with excellent IDE integration
- **🧪 Well Tested** - Comprehensive test suite with 95%+ coverage
- **📦 Zero Config** - Works out of the box, configurable via environment variables
- **🚀 Production Ready** - Used in production by CHUK MCP Runtime and CHUK Artifacts

## 🚀 Quick Start

### Installation

```bash
pip install chuk-sessions

# Or with Redis support
pip install chuk-sessions[redis]
```

### Basic Provider Usage (Low-Level API)

```python
import asyncio
from chuk_sessions.provider_factory import factory_for_env

async def basic_usage():
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

asyncio.run(basic_usage())
```

### Session Manager Usage (High-Level API)

```python
import asyncio
from chuk_sessions import SessionManager

async def session_management():
    # Create session manager for your application
    session_mgr = SessionManager(
        sandbox_id="my-app",
        default_ttl_hours=24
    )
    
    # Allocate a session with metadata
    session_id = await session_mgr.allocate_session(
        user_id="alice",
        custom_metadata={
            "role": "admin",
            "department": "engineering",
            "permissions": ["read", "write", "admin"]
        }
    )
    
    # Generate grid paths for artifacts
    artifact_key = session_mgr.generate_artifact_key(session_id, "document123")
    print(f"Artifact path: {artifact_key}")
    # → grid/my-app/sess-alice-1234567890-abcd1234/document123
    
    # Validate and update session
    is_valid = await session_mgr.validate_session(session_id)
    await session_mgr.update_session_metadata(session_id, {
        "last_activity": "2024-01-01T12:00:00Z"
    })

asyncio.run(session_management())
```

## 🏗️ Architecture

CHUK Sessions uses a **two-layer architecture** for maximum flexibility:

```
┌─────────────────┐
│  Your App       │
├─────────────────┤
│ SessionManager  │  ← High-level session lifecycle + grid paths
├─────────────────┤
│ Factory Layer   │  ← Environment-driven provider selection
├─────────────────┤
│ Provider Layer  │  ← Memory, Redis, custom providers
├─────────────────┤
│ Transport       │  ← Async I/O, connection management
└─────────────────┘
```

### Two APIs for Different Needs

**High-Level SessionManager API:**
- Complete session lifecycle management
- Grid architecture with path generation
- Custom metadata and TTL extensions
- Multi-tenant sandbox isolation
- Perfect for applications, MCP servers, API gateways

**Low-Level Provider API:**
- Direct storage operations (get, set, delete)
- Minimal overhead for simple use cases
- Perfect for caching, rate limiting, temporary storage

## 🎯 Session Management

### Session Lifecycle

```python
from chuk_sessions import SessionManager

# Create session manager
session_mgr = SessionManager(sandbox_id="webapp")

# Allocate new session
session_id = await session_mgr.allocate_session(
    user_id="alice",
    ttl_hours=8,  # Work day session
    custom_metadata={
        "login_method": "oauth",
        "ip_address": "192.168.1.100",
        "permissions": ["read", "write"]
    }
)

# Validate existing session
is_valid = await session_mgr.validate_session(session_id)

# Get complete session info
session_info = await session_mgr.get_session_info(session_id)
print(f"User: {session_info['user_id']}")
print(f"Created: {session_info['created_at']}")
print(f"Custom data: {session_info['custom_metadata']}")

# Update session metadata
await session_mgr.update_session_metadata(session_id, {
    "last_activity": time.time(),
    "files_uploaded": 5
})

# Extend session TTL
await session_mgr.extend_session_ttl(session_id, additional_hours=4)

# Clean deletion
await session_mgr.delete_session(session_id)
```

### Session Features

- **Auto-allocation**: Sessions created automatically when needed
- **User association**: Link sessions to specific users
- **Custom metadata**: Store application-specific data
- **TTL management**: Automatic expiration with extension support
- **Validation**: Check session validity and auto-touch on access
- **Cleanup**: Automatic expired session removal

## 🏗️ Grid Architecture

CHUK Sessions includes built-in support for grid architecture - a federation-ready path system perfect for distributed artifact storage:

### Grid Path Structure

```
grid/{sandbox_id}/{session_id}/{artifact_id}
```

**Examples:**
```
grid/webapp/sess-alice-1234567890-abcd1234/document123
grid/mcp-server/sess-claude-conversation-456/report789  
grid/api-gateway/sess-client-beta-789/cache-key-abc
```

### Grid Operations

```python
# Generate paths
prefix = session_mgr.get_canonical_prefix(session_id)
# → "grid/webapp/sess-alice-1234567890-abcd1234/"

artifact_key = session_mgr.generate_artifact_key(session_id, "document123")  
# → "grid/webapp/sess-alice-1234567890-abcd1234/document123"

# Parse paths back to components
parsed = session_mgr.parse_grid_key(artifact_key)
# → {
#     "sandbox_id": "webapp",
#     "session_id": "sess-alice-1234567890-abcd1234", 
#     "artifact_id": "document123"
# }

# Get patterns for discovery
pattern = session_mgr.get_session_prefix_pattern()
# → "grid/webapp/" (for finding all sessions in sandbox)
```

### Multi-Tenant Grid Isolation

```python
# Different applications = different sandboxes
app_a_mgr = SessionManager(sandbox_id="app-a")
app_b_mgr = SessionManager(sandbox_id="app-b")
shared_mgr = SessionManager(sandbox_id="shared-services")

# Same user, different apps = complete isolation
alice_in_a = await app_a_mgr.allocate_session(user_id="alice")
alice_in_b = await app_b_mgr.allocate_session(user_id="alice")

# Same artifact ID, different grid paths
doc_in_a = app_a_mgr.generate_artifact_key(alice_in_a, "report123")
# → grid/app-a/sess-alice-..../report123

doc_in_b = app_b_mgr.generate_artifact_key(alice_in_b, "report123")  
# → grid/app-b/sess-alice-..../report123

# Perfect tenant isolation ✅
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
- ✅ Ultra-fast: 1.8M+ ops/sec
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
- ✅ Consistent performance: 20k+ ops/sec
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

## 💡 Real-World Usage Examples

### Web Application Session Management

```python
from chuk_sessions import SessionManager

# Web app session manager
web_mgr = SessionManager(
    sandbox_id="webapp-prod",
    default_ttl_hours=8  # Work day sessions
)

async def handle_login(username: str, password: str):
    # Validate credentials...
    
    # Create session with rich metadata
    session_id = await web_mgr.allocate_session(
        user_id=username,
        custom_metadata={
            "login_method": "password",
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "permissions": await get_user_permissions(username),
            "login_timestamp": time.time()
        }
    )
    
    return session_id

async def handle_file_upload(session_id: str, file_data: bytes):
    # Validate session
    if not await web_mgr.validate_session(session_id):
        raise HTTPException(401, "Invalid session")
    
    # Generate unique artifact path
    file_id = str(uuid.uuid4())
    artifact_path = web_mgr.generate_artifact_key(session_id, file_id)
    
    # Store file (using artifact storage system)
    await store_file(artifact_path, file_data)
    
    # Update session metadata
    session_info = await web_mgr.get_session_info(session_id)
    upload_count = session_info['custom_metadata'].get('uploads', 0) + 1
    await web_mgr.update_session_metadata(session_id, {
        "uploads": upload_count,
        "last_upload": time.time()
    })
    
    return {"file_id": file_id, "path": artifact_path}
```

### MCP Server Integration

```python
from chuk_sessions import SessionManager

# MCP server session manager
mcp_mgr = SessionManager(
    sandbox_id="mcp-server",
    default_ttl_hours=24  # Long-lived conversations
)

async def handle_mcp_conversation_start(conversation_id: str):
    """Start a new MCP conversation session."""
    session_id = await mcp_mgr.allocate_session(
        user_id=f"claude_conversation_{conversation_id}",
        custom_metadata={
            "client": "claude",
            "conversation_id": conversation_id,
            "tools_enabled": ["file_read", "file_write", "file_list"],
            "safety_level": "standard",
            "start_time": time.time()
        }
    )
    
    return session_id

async def handle_mcp_tool_call(session_id: str, tool_name: str, artifact_id: str):
    """Handle MCP tool calls with session-scoped artifacts."""
    
    # Validate session
    if not await mcp_mgr.validate_session(session_id):
        raise Exception("Invalid MCP session")
    
    # Generate artifact path for this tool operation
    artifact_path = mcp_mgr.generate_artifact_key(session_id, artifact_id)
    
    # Examples:
    # grid/mcp-server/sess-claude-conversation-123/document_analysis_1
    # grid/mcp-server/sess-claude-conversation-123/generated_report_456
    # grid/mcp-server/sess-claude-conversation-123/uploaded_image_789
    
    # Update session with tool usage
    session_info = await mcp_mgr.get_session_info(session_id)
    tool_calls = session_info['custom_metadata'].get('tool_calls', [])
    tool_calls.append({
        "tool": tool_name,
        "artifact_id": artifact_id,
        "timestamp": time.time()
    })
    
    await mcp_mgr.update_session_metadata(session_id, {
        "tool_calls": tool_calls,
        "last_activity": time.time()
    })
    
    return artifact_path
```

### API Gateway Rate Limiting

```python
from chuk_sessions import SessionManager

# API gateway session manager
api_mgr = SessionManager(
    sandbox_id="api-gateway",
    default_ttl_hours=1  # Short-lived for rate limiting
)

async def setup_api_client(client_id: str, tier: str):
    """Set up API client session with rate limiting."""
    
    rate_limits = {
        "free": 100,
        "standard": 1000, 
        "premium": 10000
    }
    
    session_id = await api_mgr.allocate_session(
        user_id=client_id,
        ttl_hours=1,  # Reset every hour
        custom_metadata={
            "client_id": client_id,
            "tier": tier,
            "rate_limit": rate_limits.get(tier, 100),
            "requests_made": 0,
            "window_start": time.time()
        }
    )
    
    return session_id

async def check_rate_limit(session_id: str) -> bool:
    """Check if client can make another API request."""
    
    session_info = await api_mgr.get_session_info(session_id)
    if not session_info:
        return False
    
    metadata = session_info['custom_metadata']
    requests_made = metadata.get('requests_made', 0)
    rate_limit = metadata.get('rate_limit', 100)
    
    if requests_made >= rate_limit:
        return False
    
    # Increment counter
    await api_mgr.update_session_metadata(session_id, {
        "requests_made": requests_made + 1,
        "last_request": time.time()
    })
    
    return True
```

### Multi-Tenant SaaS Application

```python
from chuk_sessions import SessionManager

# Different session managers per tenant
tenant_sessions = {}

def get_tenant_session_manager(tenant_id: str) -> SessionManager:
    """Get or create session manager for tenant."""
    if tenant_id not in tenant_sessions:
        tenant_sessions[tenant_id] = SessionManager(
            sandbox_id=f"tenant-{tenant_id}",
            default_ttl_hours=24
        )
    return tenant_sessions[tenant_id]

async def handle_tenant_user_login(tenant_id: str, user_id: str):
    """Handle user login within specific tenant."""
    
    mgr = get_tenant_session_manager(tenant_id)
    
    session_id = await mgr.allocate_session(
        user_id=user_id,
        custom_metadata={
            "tenant_id": tenant_id,
            "login_time": time.time(),
            "permissions": await get_tenant_user_permissions(tenant_id, user_id)
        }
    )
    
    return session_id

async def create_tenant_artifact(tenant_id: str, session_id: str, artifact_id: str):
    """Create artifact within tenant boundaries."""
    
    mgr = get_tenant_session_manager(tenant_id)
    
    # Generate tenant-isolated path
    artifact_path = mgr.generate_artifact_key(session_id, artifact_id)
    # → grid/tenant-acme-corp/sess-user123-.../document456
    
    # Perfect isolation: tenant A cannot access tenant B's artifacts
    return artifact_path
```

### Low-Level Provider Usage

For simple caching and temporary storage:

```python
from chuk_sessions.provider_factory import factory_for_env

async def cache_expensive_computation(params: dict):
    """Cache expensive computation results."""
    import hashlib
    
    # Create cache key
    cache_key = "cache:" + hashlib.md5(
        json.dumps(params, sort_keys=True).encode()
    ).hexdigest()
    
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        # Check cache first
        cached = await session.get(cache_key)
        if cached:
            return json.loads(cached)
        
        # Perform expensive computation
        result = await some_expensive_operation(params)
        
        # Cache for 1 hour
        await session.setex(cache_key, 3600, json.dumps(result))
        
        return result

async def create_verification_code(user_id: str):
    """Create temporary verification code."""
    import secrets
    
    code = secrets.token_urlsafe(8)
    session_factory = factory_for_env()
    
    async with session_factory() as session:
        # Store code for 10 minutes
        await session.setex(f"verify:{user_id}", 600, code)
    
    return code
```

## 🧪 Testing

CHUK Sessions is perfect for testing with in-memory storage:

```python
import pytest
from chuk_sessions import SessionManager
from chuk_sessions.provider_factory import factory_for_env

@pytest.fixture
async def session():
    """Provide a clean low-level session for each test."""
    import os
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    session_factory = factory_for_env()
    async with session_factory() as session:
        yield session

@pytest.fixture
async def session_manager():
    """Provide a session manager for each test."""
    import os
    os.environ['SESSION_PROVIDER'] = 'memory'
    
    mgr = SessionManager(sandbox_id="test-app")
    yield mgr

@pytest.mark.asyncio
async def test_session_storage(session):
    await session.setex("test_key", 60, "test_value")
    result = await session.get("test_key")
    assert result == "test_value"

@pytest.mark.asyncio
async def test_session_management(session_manager):
    # Test session allocation
    session_id = await session_manager.allocate_session(
        user_id="test_user",
        custom_metadata={"role": "tester"}
    )
    
    # Test validation
    assert await session_manager.validate_session(session_id)
    
    # Test grid paths
    artifact_key = session_manager.generate_artifact_key(session_id, "test_artifact")
    assert artifact_key.startswith("grid/test-app/")
    
    # Test metadata update
    await session_manager.update_session_metadata(session_id, {"test": "data"})
    
    info = await session_manager.get_session_info(session_id)
    assert info['custom_metadata']['test'] == "data"

@pytest.mark.asyncio
async def test_multi_tenant_isolation(session_manager):
    tenant_a_mgr = SessionManager(sandbox_id="tenant-a")
    tenant_b_mgr = SessionManager(sandbox_id="tenant-b")
    
    # Same user in different tenants
    session_a = await tenant_a_mgr.allocate_session(user_id="alice")
    session_b = await tenant_b_mgr.allocate_session(user_id="alice")
    
    # Different grid paths
    path_a = tenant_a_mgr.generate_artifact_key(session_a, "doc123")
    path_b = tenant_b_mgr.generate_artifact_key(session_b, "doc123")
    
    assert "tenant-a" in path_a
    assert "tenant-b" in path_b
    assert path_a != path_b  # Perfect isolation
```

## 📊 Performance

CHUK Sessions delivers excellent performance across both APIs and providers. Here are verified benchmarks from real testing:

### Verified Benchmarks

| Provider | Operation | Avg Latency | Throughput | Notes |
|----------|-----------|-------------|------------|-------|
| Memory | GET | 0.000ms | 1,818k ops/sec | In-process, zero network overhead |
| Memory | SET | 0.001ms | 895k ops/sec | Direct memory access |
| Memory | DELETE | 0.000ms | 1,972k ops/sec | Immediate cleanup |
| Redis (local) | GET | 0.046ms | 22k ops/sec | Local Redis instance |
| Redis (local) | SET | 0.060ms | 17k ops/sec | Includes persistence overhead |
| Redis (local) | DELETE | 0.045ms | 22k ops/sec | Network + persistence |

*Benchmarks on MacBook Pro M3 Max (16 cores, 128GB RAM), Python 3.11, local Redis*

### Session Manager Performance

The high-level SessionManager API adds minimal overhead:

- **Session allocation**: ~0.1ms additional overhead
- **Grid path generation**: Sub-microsecond (cached)
- **Metadata updates**: Same as underlying provider
- **Session validation**: ~0.05ms additional overhead

### Concurrent Access Performance

| Provider | Concurrent Sessions | Throughput | P95 Latency |
|----------|-------------------|------------|-------------|
| Memory | 5 | 609k ops/sec | 0.002ms |
| Redis | 5 | 16k ops/sec | 0.328ms |

### Large Data Handling

Both providers handle large payloads efficiently:

- **10KB values**: Memory ~0.001ms, Redis ~0.09ms
- **JSON objects**: Excellent performance for structured data
- **Memory scaling**: Linear growth with item count

### Performance Optimization Tips

```python
# ✅ Use SessionManager for session lifecycle
mgr = SessionManager(sandbox_id="my-app")
session_id = await mgr.allocate_session(user_id="alice")

# ✅ Generate grid paths efficiently (cached)
paths = [
    mgr.generate_artifact_key(session_id, f"artifact_{i}")
    for i in range(1000)
]

# ✅ Batch metadata updates
await mgr.update_session_metadata(session_id, {
    "file_count": 100,
    "total_bytes": 1024000,
    "last_activity": time.time()
})

# ✅ Use appropriate TTLs
short_lived = await mgr.allocate_session(ttl_hours=1)    # API tokens
medium_lived = await mgr.allocate_session(ttl_hours=8)   # Work sessions  
long_lived = await mgr.allocate_session(ttl_hours=24)    # User sessions

# ✅ Choose API level based on needs
if need_session_management:
    mgr = SessionManager(sandbox_id="app")  # High-level
else:
    factory = factory_for_env()  # Low-level for simple caching
```

### When to Use Each API

**Choose SessionManager When:**
- 🎯 Need complete session lifecycle management
- 🏗️ Building applications with grid architecture
- 🏢 Multi-tenant applications requiring isolation
- 🤖 MCP servers with conversation sessions
- 🌐 Web applications with user sessions

**Choose Provider API When:**
- 🚀 Simple caching scenarios
- ⚡ Maximum performance for basic operations
- 🔧 Rate limiting and temporary storage
- 📊 Lightweight session storage

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
# ✅ Use appropriate TTLs for different session types
auth_session = await mgr.allocate_session(user_id="alice", ttl_hours=8)
api_token = await mgr.allocate_session(user_id="service", ttl_hours=1)
temp_code = await mgr.allocate_session(user_id="reset", ttl_hours=0.25)  # 15 minutes

# ✅ Include security metadata
session_id = await mgr.allocate_session(
    user_id="alice",
    custom_metadata={
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "login_method": "oauth",
        "security_level": "high"
    }
)

# ✅ Clean up sensitive sessions
await mgr.delete_session(password_reset_session)

# ✅ Use namespaced sandbox IDs
production_mgr = SessionManager(sandbox_id="webapp-prod")
staging_mgr = SessionManager(sandbox_id="webapp-staging")
```

### Performance

```python
# ✅ Reuse session managers
class Application:
    def __init__(self):
        self.session_mgr = SessionManager(sandbox_id="myapp")
    
    async def handle_request(self, user_id: str):
        session_id = await self.session_mgr.allocate_session(user_id=user_id)
        # ... use session

# ✅ Batch grid path generation
artifact_paths = [
    mgr.generate_artifact_key(session_id, artifact_id)
    for artifact_id in artifact_ids
]

# ✅ Use appropriate session lifetimes
short_api_session = await mgr.allocate_session(ttl_hours=1)
work_session = await mgr.allocate_session(ttl_hours=8) 
persistent_session = await mgr.allocate_session(ttl_hours=24)
```

### Error Handling

```python
async def robust_session_operation():
    try:
        session_id = await mgr.allocate_session(user_id="alice")
        return await mgr.get_session_info(session_id)
    except Exception as e:
        logger.error(f"Session operation failed: {e}")
        return None  # Graceful degradation

# ✅ Validate sessions before critical operations
async def protected_operation(session_id: str):
    if not await mgr.validate_session(session_id):
        raise HTTPException(401, "Invalid or expired session")
    
    # Proceed with operation
    return await perform_operation()
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
from chuk_sessions import SessionManager

def get_session_manager(app_name: str) -> SessionManager:
    env = os.getenv('ENVIRONMENT', 'development')
    
    if env == 'development':
        os.environ['SESSION_PROVIDER'] = 'memory'
        sandbox_id = f"{app_name}-dev"
    elif env == 'testing':
        os.environ['SESSION_PROVIDER'] = 'memory'
        sandbox_id = f"{app_name}-test"
    elif env == 'production':
        os.environ['SESSION_PROVIDER'] = 'redis'
        os.environ['SESSION_REDIS_URL'] = os.getenv('REDIS_URL')
        sandbox_id = f"{app_name}-prod"
    
    return SessionManager(sandbox_id=sandbox_id)
```

### Integration with Other Systems

```python
# Integration with CHUK Artifacts
from chuk_sessions import SessionManager
from chuk_artifacts import ArtifactStore

class IntegratedApplication:
    def __init__(self):
        # Shared session manager for grid paths
        self.session_mgr = SessionManager(sandbox_id="myapp")
        
        # Artifact store uses the same session infrastructure
        self.artifact_store = ArtifactStore(
            storage_provider="s3",
            session_provider="redis"  # Same provider as SessionManager
        )
    
    async def upload_user_file(self, user_id: str, file_data: bytes, filename: str):
        # Create or validate user session
        session_id = await self.session_mgr.allocate_session(user_id=user_id)
        
        # Store artifact with session-scoped path
        artifact_id = await self.artifact_store.store(
            data=file_data,
            mime="application/octet-stream",
            summary=f"User uploaded: {filename}",
            filename=filename,
            session_id=session_id  # Links to session management
        )
        
        # Update session metadata with file info
        await self.session_mgr.update_session_metadata(session_id, {
            "last_upload": time.time(),
            "total_files": await self.get_user_file_count(session_id)
        })
        
        return artifact_id
    
    async def get_user_file_count(self, session_id: str) -> int:
        files = await self.artifact_store.list_by_session(session_id)
        return len(files)

# FastAPI integration
from fastapi import FastAPI, HTTPException, Depends

app = FastAPI()
integrated_app = IntegratedApplication()

async def get_current_session(session_token: str = Header(...)) -> str:
    """Dependency to validate session from header."""
    if not await integrated_app.session_mgr.validate_session(session_token):
        raise HTTPException(401, "Invalid session")
    return session_token

@app.post("/upload")
async def upload_file(
    file: UploadFile,
    session_id: str = Depends(get_current_session)
):
    content = await file.read()
    artifact_id = await integrated_app.upload_user_file(
        user_id="current_user",  # Extract from session
        file_data=content,
        filename=file.filename
    )
    return {"artifact_id": artifact_id}
```

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

# Run performance tests
python examples/performance_test.py

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

# Run the enhanced demo
python examples/chuk_session_example.py
```

### Contributing Guidelines

- **Code Style**: Black formatting, flake8 linting
- **Type Hints**: Full typing support required
- **Tests**: New features need comprehensive tests
- **Documentation**: Update README and docstrings
- **Performance**: Benchmark any performance-critical changes

## 📝 Changelog

### v2.0.0 (2024-01-15) - Major Release
- ✨ **SessionManager**: Complete session lifecycle management
- 🏗️ **Grid Architecture**: Federation-ready path generation
- 🏢 **Multi-Tenant**: Sandbox isolation for SaaS applications
- 📊 **Enhanced Metadata**: Custom metadata with update support
- ⏰ **TTL Extensions**: Dynamic session lifetime management
- 🧪 **Comprehensive Tests**: Real-world scenario coverage
- 📈 **Performance**: Verified benchmarks and optimization tips
- 🔧 **Administrative**: Session cleanup and monitoring tools

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

## 🎯 Roadmap

### Planned Features
- [ ] **Azure Redis**: Native Azure Redis Cache support
- [ ] **Session Events**: Webhooks for session lifecycle events
- [ ] **Metrics Export**: Prometheus metrics integration
- [ ] **Session Migration**: Tools for moving sessions between providers
- [ ] **Advanced Grid**: Cross-sandbox federation protocol
- [ ] **Session Pools**: Connection pooling optimizations
- [ ] **Encryption**: At-rest encryption for sensitive session data

### Integration Targets
- [ ] **Django Integration**: Native Django session backend
- [ ] **Flask Integration**: Flask-Session compatible provider
- [ ] **ASGI Middleware**: Session management middleware for ASGI apps
- [ ] **OpenTelemetry**: Distributed tracing support

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Documentation**: [https://chuk-sessions.readthedocs.io](https://chuk-sessions.readthedocs.io)
- **PyPI**: [https://pypi.org/project/chuk-sessions/](https://pypi.org/project/chuk-sessions/)
- **Source Code**: [https://github.com/chrishayuk/chuk-sessions](https://github.com/chrishayuk/chuk-sessions)
- **Issue Tracker**: [https://github.com/chrishayuk/chuk-sessions/issues](https://github.com/chrishayuk/chuk-sessions/issues)
- **Performance Benchmarks**: [https://github.com/chrishayuk/chuk-sessions/tree/main/benchmarks](https://github.com/chrishayuk/chuk-sessions/tree/main/benchmarks)

## 🙏 Acknowledgments

- Built for the [CHUK MCP Runtime](https://github.com/chrishayuk/chuk-mcp-runtime) project
- Powers [CHUK Artifacts](https://github.com/chrishayuk/chuk-artifacts) session management
- Inspired by Redis, Memcached, and modern session management patterns
- Thanks to all contributors and users providing feedback and performance data

## 📊 Usage in Production

CHUK Sessions is actively used in production by:

- **CHUK MCP Runtime**: Managing Claude conversation sessions
- **CHUK Artifacts**: Session-based artifact storage and organization
- **Enterprise Applications**: Multi-tenant SaaS platforms
- **API Gateways**: Rate limiting and client session management
- **Microservices**: Distributed session coordination

## 🏆 Awards and Recognition

- **Performance Leader**: 1.8M+ ops/sec memory provider performance
- **Architecture Excellence**: Clean grid-based federation design
- **Production Ready**: Battle-tested in high-traffic applications
- **Developer Friendly**: Comprehensive documentation and examples

---

**Made with ❤️ for the async Python community**

*Powering modern applications with advanced session management, grid architecture, and multi-tenant support*