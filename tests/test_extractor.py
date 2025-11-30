"""Tests for core/extractor.py."""

# pylint: disable=missing-function-docstring,redefined-outer-name

import asyncio
import json
from dataclasses import dataclass, field
from types import MethodType
from typing import Optional

import pytest

from spf_guru.core.cache import CacheManager, MemoryCache
from spf_guru.core.config import Settings
from spf_guru.core.extractor import SPFExtractor


@dataclass
class FakeDNSResolver:
    """Fake DNS resolver for testing with predefined responses."""

    # Map domain -> TXT records
    txt_records: dict[str, list[str]] = field(default_factory=dict)
    # Map domain -> A records
    a_records: dict[str, list[str]] = field(default_factory=dict)
    # Map domain -> AAAA records
    aaaa_records: dict[str, list[str]] = field(default_factory=dict)
    # Map domain -> MX IPs
    mx_records: dict[str, list[str]] = field(default_factory=dict)
    # Default TTL for all records
    default_ttl: int = 300

    async def get_txt_records(self, domain: str) -> tuple[list[str], Optional[int]]:
        records = self.txt_records.get(domain, [])
        return records, self.default_ttl if records else None

    async def resolve_a(self, domain: str) -> tuple[list[str], Optional[int]]:
        records = self.a_records.get(domain, [])
        return records, self.default_ttl if records else None

    async def resolve_aaaa(self, domain: str) -> tuple[list[str], Optional[int]]:
        records = self.aaaa_records.get(domain, [])
        return records, self.default_ttl if records else None

    async def get_mx_ips(self, domain: str) -> tuple[list[str], list[Optional[int]]]:
        records = self.mx_records.get(domain, [])
        ttls = [self.default_ttl] * len(records) if records else []
        return records, ttls


@pytest.fixture
def test_settings():
    """Settings for testing."""
    return Settings(
        zone="test.spf.guru",
        default_ttl=300,
        _env_file=None,
    )


@pytest.fixture
def test_cache():
    """Fresh cache manager for each test."""
    return CacheManager(backend=MemoryCache())


class TestSPFExtraction:
    """Integration tests for SPF extraction."""

    async def test_no_spf_record_returns_empty(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["not an spf record", "some other txt"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, macros, _ttls, invalid = await extractor.extract_spf("example.com")

        assert ips == []
        assert macros == []
        assert invalid == []

    async def test_extracts_ip4_addresses(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.1 ~all"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "192.168.1.0/24" in ips
        assert "10.0.0.1" in ips

    async def test_extracts_ip6_addresses(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 ip6:2001:db8::/32 ~all"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "2001:db8::/32" in ips

    async def test_invalid_ip_goes_to_invalid_list(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 ip4:not_an_ip ~all"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, invalid = await extractor.extract_spf("example.com")

        assert "not_an_ip" in invalid
        assert len(ips) == 0

    async def test_extracts_macros(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 exists:%{i}._spf.example.com ~all"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        _, macros, _, _ = await extractor.extract_spf("example.com")

        assert len(macros) > 0
        assert any("%{" in m for m in macros)

    async def test_resolves_a_mechanism(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 a ~all"]},
            a_records={"example.com": ["93.184.216.34"]},
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "93.184.216.34" in ips

    async def test_resolves_a_with_domain(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 a:mail.example.com ~all"]},
            a_records={"mail.example.com": ["192.168.1.100"]},
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "192.168.1.100" in ips

    async def test_resolves_mx_mechanism(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 mx ~all"]},
            mx_records={"example.com": ["192.168.1.10", "192.168.1.11"]},
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "192.168.1.10" in ips
        assert "192.168.1.11" in ips

    async def test_follows_includes(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={
                "example.com": ["v=spf1 include:_spf.google.com ~all"],
                "_spf.google.com": ["v=spf1 ip4:172.217.0.0/16 ~all"],
            }
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "172.217.0.0/16" in ips

    async def test_follows_redirect(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={
                "example.com": ["v=spf1 redirect=_spf.example.net"],
                "_spf.example.net": ["v=spf1 ip4:10.0.0.0/8 ~all"],
            }
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "10.0.0.0/8" in ips

    async def test_prevents_circular_includes(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={
                "a.com": ["v=spf1 include:b.com ~all"],
                "b.com": ["v=spf1 include:a.com ip4:1.2.3.4 ~all"],
            }
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        # Should not infinite loop
        ips, _, _, _ = await extractor.extract_spf("a.com")

        assert "1.2.3.4" in ips

    async def test_handles_nested_includes(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={
                "example.com": ["v=spf1 include:level1.com ~all"],
                "level1.com": ["v=spf1 include:level2.com ip4:1.1.1.1 ~all"],
                "level2.com": ["v=spf1 ip4:2.2.2.2 ~all"],
            }
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("example.com")

        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips

    async def test_ignores_spf_guru_macros(self, test_settings, test_cache):
        """SPF Guru's own macro tokens should be ignored."""
        resolver = FakeDNSResolver(
            txt_records={
                "example.com": [
                    "v=spf1 include:i.%{ir}._d.%{d}.test.spf.guru ip4:1.2.3.4 ~all"
                ]
            }
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, macros, _, _ = await extractor.extract_spf("example.com")

        assert "1.2.3.4" in ips
        # SPF Guru macro should not appear in macros list
        assert not any("test.spf.guru" in m for m in macros)


class TestGetOrComputeSPF:
    """Integration tests for caching behavior."""

    async def test_caches_result(self, test_settings, test_cache):
        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 ip4:1.2.3.4 ~all"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        result1 = await extractor.get_or_compute_spf("example.com")
        result2 = await extractor.get_or_compute_spf("example.com")

        assert result1 == result2
        # Verify it was cached by checking we can retrieve it
        cached = await test_cache.get("spf:example.com")
        assert cached is not None

    async def test_returns_cached_result(self, test_settings, test_cache):
        # Pre-populate cache
        cached_data = {
            "domain": "example.com",
            "ips": ["cached.ip"],
            "macro_records": [],
            "invalid_addr": [],
        }
        await test_cache.set("spf:example.com", json.dumps(cached_data), ttl=300)

        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 ip4:different.ip ~all"]}
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        result = await extractor.get_or_compute_spf("example.com")

        # Should return cached data, not fresh DNS result
        assert result["ips"] == ["cached.ip"]

    async def test_in_flight_protection(self, test_settings, test_cache):
        """Concurrent requests for same domain should share work."""
        call_count = 0
        original_get_txt = FakeDNSResolver.get_txt_records

        async def slow_get_txt(self, domain):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            return await original_get_txt(self, domain)

        resolver = FakeDNSResolver(
            txt_records={"example.com": ["v=spf1 ip4:1.2.3.4 ~all"]}
        )
        resolver.get_txt_records = MethodType(slow_get_txt, resolver)

        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        # Launch concurrent requests
        results = await asyncio.gather(
            extractor.get_or_compute_spf("example.com"),
            extractor.get_or_compute_spf("example.com"),
        )

        assert results[0] == results[1]
        # DNS should only be queried once
        assert call_count == 1


class TestRealWorldSPFRecords:
    """Test with realistic SPF record patterns."""

    async def test_google_like_spf(self, test_settings, test_cache):
        """Test a Google-style SPF setup with multiple includes."""
        resolver = FakeDNSResolver(
            txt_records={
                "company.com": ["v=spf1 include:_spf.google.com ~all"],
                "_spf.google.com": [
                    "v=spf1 include:_netblocks.google.com "
                    + "include:_netblocks2.google.com ~all"
                ],
                "_netblocks.google.com": [
                    "v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"
                ],
                "_netblocks2.google.com": ["v=spf1 ip4:172.217.0.0/19 ~all"],
            }
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("company.com")

        assert "35.190.247.0/24" in ips
        assert "64.233.160.0/19" in ips
        assert "172.217.0.0/19" in ips

    async def test_mixed_mechanisms(self, test_settings, test_cache):
        """Test SPF with ip4, ip6, a, mx, and include."""
        resolver = FakeDNSResolver(
            txt_records={
                "mixed.com": [
                    "v=spf1 ip4:1.2.3.4 ip6:2001:db8::1 a mx include:other.com ~all"
                ],
                "other.com": ["v=spf1 ip4:5.6.7.8 ~all"],
            },
            a_records={"mixed.com": ["10.0.0.1"]},
            aaaa_records={"mixed.com": ["2001:db8::2"]},
            mx_records={"mixed.com": ["10.0.0.2"]},
        )
        extractor = SPFExtractor(
            settings=test_settings, resolver=resolver, cache=test_cache
        )

        ips, _, _, _ = await extractor.extract_spf("mixed.com")

        assert "1.2.3.4" in ips
        assert "2001:db8::1" in ips
        assert "10.0.0.1" in ips
        assert "2001:db8::2" in ips
        assert "10.0.0.2" in ips
        assert "5.6.7.8" in ips
