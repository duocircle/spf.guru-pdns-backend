"""Cache abstraction layer supporting Redis and in-memory backends."""

# pylint: disable=missing-function-docstring

import logging
from typing import Optional, Protocol

import redis.asyncio as aioredis
from aiocache import SimpleMemoryCache


logger = logging.getLogger(__name__)


class CacheBackend(Protocol):
    """Protocol for cache backends."""

    async def get(self, key: str) -> Optional[str]: ...
    async def set(self, key: str, value: str, ttl: int) -> None: ...
    async def delete(self, key: str) -> bool: ...


class RedisCache:
    """Redis cache backend."""

    def __init__(self, url: str):
        self._client = aioredis.from_url(
            url,
            encoding="utf-8",
            decode_responses=True,
        )

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis."""
        return await self._client.get(key)

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set value in Redis with TTL."""
        await self._client.set(key, value, ex=ttl)

    async def delete(self, key: str) -> bool:
        """Delete key from Redis. Returns True if key existed."""
        return await self._client.delete(key) > 0


class MemoryCache:
    """In-memory cache backend using aiocache."""

    def __init__(self):
        self._cache = SimpleMemoryCache()

    async def get(self, key: str) -> Optional[str]:
        """Get value from memory cache."""
        return await self._cache.get(key)

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set value in memory cache with TTL."""
        await self._cache.set(key, value, ttl=ttl)

    async def delete(self, key: str) -> bool:
        """Delete key from memory cache. Returns True if key existed."""
        return await self._cache.delete(key)


class CacheManager:
    """Manages cache backend initialization and access."""

    def __init__(self, backend: Optional[CacheBackend] = None):
        self._backend = backend

    def configure(self, use_redis: bool = False, redis_url: Optional[str] = None):
        """Configure the cache backend."""
        if use_redis and redis_url:
            self._backend = RedisCache(redis_url)
        else:
            self._backend = MemoryCache()

    def _get_backend(self) -> CacheBackend:
        """Get the cache backend, initializing with memory cache if needed."""
        if self._backend is None:
            self._backend = MemoryCache()

        return self._backend

    async def get(self, key: str) -> Optional[str]:
        """Get value from cache."""
        return await self._get_backend().get(key)

    async def set(self, key: str, value: str, ttl: int, log: bool = False) -> None:
        """Set value in cache with TTL."""
        await self._get_backend().set(key, value, ttl)

        if log:
            logger.info(f"{key} added to cache")

    async def delete(self, key: str) -> bool:
        """Delete key from cache. Returns True if key existed."""
        deleted = await self._get_backend().delete(key)

        if deleted:
            logger.info(f"{key} removed from cache")

        return deleted


# Default cache manager instance
_cache_manager: Optional[CacheManager] = None


def get_cache_manager() -> CacheManager:
    """Get or create the default cache manager."""
    global _cache_manager

    if _cache_manager is None:
        _cache_manager = CacheManager()

    return _cache_manager


def init_cache(use_redis: bool = False, redis_url: Optional[str] = None) -> None:
    """Initialize cache with settings. Call at app startup."""
    get_cache_manager().configure(use_redis, redis_url)


def set_cache_manager(manager: CacheManager) -> None:
    """Set a custom cache manager (useful for testing)."""
    global _cache_manager

    _cache_manager = manager


def reset_cache_manager() -> None:
    """Reset the cache manager (useful for testing)."""
    global _cache_manager

    _cache_manager = None


async def cache_get(key: str) -> Optional[str]:
    """Get value from cache."""
    return await get_cache_manager().get(key)


async def cache_set(key: str, value: str, ttl: int, log: bool = False) -> None:
    """Set value in cache with TTL."""
    await get_cache_manager().set(key, value, ttl, log)


async def cache_delete(key: str) -> bool:
    """Delete key from cache. Returns True if key existed."""
    return await get_cache_manager().delete(key)
