# -*- coding: utf-8 -*-
# chuk_sessions/providers/redis.py
"""Redis-backed session store (wraps redis.asyncio)."""

from __future__ import annotations

import logging
import os
import ssl
from contextlib import asynccontextmanager
from typing import Callable, AsyncContextManager

from ..exceptions import ProviderError

logger = logging.getLogger(__name__)

# Try to import redis, but make it optional
try:
    import redis.asyncio as aioredis  # type: ignore[import-not-found]
    from redis.asyncio.cluster import RedisCluster, ClusterNode  # type: ignore[import-not-found]

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None
    RedisCluster = None
    ClusterNode = None

_DEF_URL = os.getenv(
    "SESSION_REDIS_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0")
)
_tls_insecure = os.getenv("REDIS_TLS_INSECURE", "0") == "1"


# SSL configuration for both standalone and cluster
def _get_ssl_kwargs(for_cluster: bool = False, url: str = ""):
    """
    Get SSL kwargs compatible with both Redis and RedisCluster.

    Args:
        for_cluster: If True, return cluster-compatible SSL kwargs
        url: The Redis URL (to detect if TLS is needed)

    Returns:
        Dict of SSL configuration parameters
    """
    # Check if URL uses TLS (rediss://)
    is_tls_url = url.startswith("rediss://")

    if _tls_insecure and is_tls_url:
        # For cluster mode, pass SSL params directly
        if for_cluster:
            return {
                "ssl": True,
                "ssl_cert_reqs": ssl.CERT_NONE,
                "ssl_check_hostname": False,
            }
        # For from_url() with rediss://, pass cert verification override
        else:
            return {"ssl_cert_reqs": ssl.CERT_NONE}

    # No SSL parameters for non-TLS URLs
    return {}


# Default TTL from environment or 1 hour
_DEFAULT_TTL = int(os.getenv("SESSION_DEFAULT_TTL", "3600"))


def _check_redis_available():
    """Raise a helpful error if redis is not available."""
    if not REDIS_AVAILABLE:
        raise ProviderError(
            "Redis provider requires the 'redis' package. "
            "Install it with: pip install chuk-sessions[redis]"
        )


def _parse_cluster_url(url: str) -> list:
    """
    Parse a cluster URL into a list of ClusterNode objects.

    Supported formats:
        redis://host1:7000,host2:7001,host3:7002
        redis://host1:7000,host2:7001,host3:7002/0  (removes /0)

    Returns:
        List of ClusterNode objects
    """
    # Remove redis:// or rediss:// prefix
    url = url.replace("redis://", "").replace("rediss://", "")

    # Remove database selector if present (not supported in cluster mode)
    if "/" in url:
        url = url.split("/")[0]

    # Parse comma-separated hosts
    nodes = []
    for host_port in url.split(","):
        host_port = host_port.strip()
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            nodes.append(ClusterNode(host=host, port=int(port)))
        else:
            # Default Redis port
            nodes.append(ClusterNode(host=host_port, port=6379))

    return nodes


def _create_redis_client(url: str):
    """
    Create a Redis client with automatic cluster detection.

    If URL contains comma-separated hosts, creates RedisCluster.
    Otherwise, creates standard Redis client.

    Args:
        url: Redis connection URL

    Returns:
        Redis or RedisCluster client instance
    """
    _check_redis_available()

    # Detect cluster URL (multiple hosts separated by commas)
    if "," in url:
        logger.info("Detected Redis Cluster URL with multiple hosts")
        nodes = _parse_cluster_url(url)
        logger.info(f"Connecting to Redis Cluster with {len(nodes)} nodes: {nodes}")

        ssl_kwargs = _get_ssl_kwargs(for_cluster=True, url=url)

        return RedisCluster(
            startup_nodes=nodes,
            decode_responses=True,
            require_full_coverage=True,  # Ensure full cluster coverage
            max_connections=50,  # Connection pool per node
            **ssl_kwargs,
        )
    else:
        # Single node - use standard Redis
        logger.debug(f"Connecting to standalone Redis: {url}")

        # Remove /0 database selector if present (for smooth cluster transition)
        url_clean = url
        if url.endswith("/0"):
            url_clean = url[:-2]
            logger.debug(f"Removed /0 database selector: {url_clean}")

        ssl_kwargs = _get_ssl_kwargs(for_cluster=False, url=url_clean)

        return aioredis.from_url(url_clean, decode_responses=True, **ssl_kwargs)


class _RedisSession:
    def __init__(self, url: str = _DEF_URL):
        _check_redis_available()
        try:
            self._r = _create_redis_client(url)
            self._is_cluster = (
                isinstance(self._r, RedisCluster) if RedisCluster else False
            )
            logger.debug(
                f"Created {'cluster' if self._is_cluster else 'standalone'} Redis session"
            )
        except Exception as err:
            logger.error("Failed to connect to Redis at %s: %s", url, err)
            raise ProviderError(f"Redis connection failed: {err}") from err

    async def set(self, key: str, value: str):
        """Set a key-value pair with the default TTL."""
        await self.setex(key, _DEFAULT_TTL, value)

    async def setex(self, key: str, ttl: int, value: str):
        """Set a key-value pair with explicit TTL in seconds."""
        try:
            await self._r.setex(key, ttl, value)
        except Exception as err:
            logger.error("Redis setex failed for key %s: %s", key, err)
            raise

    async def get(self, key: str):
        """Get a value by key."""
        try:
            return await self._r.get(key)
        except Exception as err:
            logger.error("Redis get failed for key %s: %s", key, err)
            raise

    async def delete(self, key: str):
        """Delete a key from Redis."""
        try:
            return await self._r.delete(key)
        except Exception as err:
            logger.error("Redis delete failed for key %s: %s", key, err)
            raise

    async def close(self):
        await self._r.close()


def factory(url: str = _DEF_URL) -> Callable[[], AsyncContextManager]:
    """Create a Redis session factory."""
    _check_redis_available()

    @asynccontextmanager
    async def _ctx():
        client = _RedisSession(url)
        try:
            yield client
        finally:
            await client.close()

    return _ctx
