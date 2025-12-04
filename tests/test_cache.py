"""Tests for core/cache.py."""

# pylint: disable=missing-function-docstring

import pytest

from spf_guru.core.cache import (
    CacheManager,
    MemoryCache,
    cache_get,
    cache_set,
    reset_cache_manager,
    set_cache_manager,
)


class TestMemoryCache:
    """Tests for MemoryCache class."""

    @pytest.fixture
    def memory_cache(self):
        return MemoryCache()

    async def test_get_returns_none_for_missing_key(self, memory_cache):
        result = await memory_cache.get("nonexistent")
        assert result is None

    async def test_set_and_get(self, memory_cache):
        await memory_cache.set("test_key", "test_value", ttl=300)
        result = await memory_cache.get("test_key")
        assert result == "test_value"

    async def test_set_overwrites_existing_value(self, memory_cache):
        await memory_cache.set("key", "value1", ttl=300)
        await memory_cache.set("key", "value2", ttl=300)
        result = await memory_cache.get("key")
        assert result == "value2"


class TestCacheManager:
    """Tests for CacheManager class."""

    async def test_default_uses_memory_cache(self):
        manager = CacheManager()
        # Should auto-initialize to MemoryCache
        result = await manager.get("nonexistent")
        assert result is None

    async def test_set_and_get(self):
        manager = CacheManager()
        await manager.set("key", "value", ttl=300)
        result = await manager.get("key")
        assert result == "value"

    async def test_configure_memory_cache(self):
        manager = CacheManager()
        manager.configure(use_redis=False)
        await manager.set("key", "value", ttl=300)
        result = await manager.get("key")
        assert result == "value"

    async def test_inject_custom_backend(self):
        """Test dependency injection with custom backend."""
        custom_backend = MemoryCache()
        await custom_backend.set("injected", "value", ttl=300)

        manager = CacheManager(backend=custom_backend)
        result = await manager.get("injected")
        assert result == "value"

    async def test_log_output(self, caplog):
        manager = CacheManager()
        with caplog.at_level("INFO"):
            await manager.set("key", "value", ttl=300, log=True)
        assert "key added to cache" in caplog.text


class TestModuleFunctions:
    """Tests for module-level cache_get and cache_set functions."""

    @pytest.fixture(autouse=True)
    def reset_manager(self):
        """Reset cache manager before and after each test."""
        reset_cache_manager()
        yield
        reset_cache_manager()

    async def test_cache_get_returns_none_for_missing(self):
        result = await cache_get("nonexistent")
        assert result is None

    async def test_cache_set_and_get(self):
        await cache_set("key", "value", ttl=300)
        result = await cache_get("key")
        assert result == "value"

    async def test_inject_custom_manager(self):
        """Test that we can inject a custom manager for testing."""
        custom_manager = CacheManager()
        await custom_manager.set("custom_key", "custom_value", ttl=300)

        set_cache_manager(custom_manager)

        result = await cache_get("custom_key")
        assert result == "custom_value"
