"""Pytest configuration and fixtures."""

# pylint: disable=redefined-outer-name

import os
from unittest.mock import AsyncMock, patch

import pytest

from spf_guru.core.config import Settings

# Set test environment variables before importing application code
os.environ.setdefault("ZONE", "test.spf.guru")
os.environ.setdefault("SOA_SERIAL", "2025010100")
os.environ.setdefault("SOA_HOSTMASTER", "hostmaster@test.com")
os.environ.setdefault("NS_RECORDS", "ns1.test.com ns2.test.com")


@pytest.fixture
def mock_settings():
    """Provide test settings with predictable values."""
    return Settings(
        zone="test.spf.guru",
        soa_serial="2025010100",
        soa_hostmaster="hostmaster@test.com",
        ns_records="ns1.test.com ns2.test.com",
        redis_ip=None,
        default_ttl=300,
        max_chain=9,
    )


@pytest.fixture
def mock_get_settings(mock_settings):
    """Patch get_settings to return test settings."""
    with patch("spf_guru.core.config.get_settings", return_value=mock_settings):
        yield mock_settings


@pytest.fixture
def mock_cache():
    """Mock cache functions."""
    with (
        patch("spf_guru.core.cache.cache_get", new_callable=AsyncMock) as mock_get,
        patch("spf_guru.core.cache.cache_set", new_callable=AsyncMock) as mock_set,
    ):
        mock_get.return_value = None  # Default: cache miss
        yield {"get": mock_get, "set": mock_set}


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver functions."""
    with (
        patch(
            "spf_guru.dns.resolver.get_txt_records", new_callable=AsyncMock
        ) as mock_txt,
        patch("spf_guru.dns.resolver.resolve_a", new_callable=AsyncMock) as mock_a,
        patch(
            "spf_guru.dns.resolver.resolve_aaaa", new_callable=AsyncMock
        ) as mock_aaaa,
        patch("spf_guru.dns.resolver.get_mx_ips", new_callable=AsyncMock) as mock_mx,
    ):
        yield {
            "txt": mock_txt,
            "a": mock_a,
            "aaaa": mock_aaaa,
            "mx": mock_mx,
        }
