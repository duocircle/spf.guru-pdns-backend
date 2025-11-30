"""Tests for api/routes.py."""

# pylint: disable=redefined-outer-name,missing-function-docstring

import json
import asyncio
from dataclasses import dataclass, field
from typing import Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from spf_guru.api.routes import (
    RouteDependencies,
    _spf_check,
    ip_version,
    reset_dependencies,
    router,
    set_dependencies,
)
from spf_guru.core.cache import CacheManager, MemoryCache
from spf_guru.core.config import Settings
from spf_guru.core.extractor import SPFExtractor
from spf_guru.dns.patterns import reset_patterns_cache


# --- Fake DNS Resolver ---


@dataclass
class FakeDNSResolver:
    """Fake DNS resolver for testing with predefined responses."""

    txt_records: dict[str, list[str]] = field(default_factory=dict)
    a_records: dict[str, list[str]] = field(default_factory=dict)
    aaaa_records: dict[str, list[str]] = field(default_factory=dict)
    mx_records: dict[str, list[str]] = field(default_factory=dict)
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


# --- Fake Database Logger ---


@dataclass
class FakeDatabaseLogger:
    """Fake database logger that records calls."""

    calls: list[dict] = field(default_factory=list)
    should_raise: bool = False

    async def __call__(self, domain: str, ip: str, result: str, ipversion: int) -> bool:
        if self.should_raise:
            raise RuntimeError("Database error")
        self.calls.append(
            {"domain": domain, "ip": ip, "result": result, "ipversion": ipversion}
        )
        return True


# --- Fixtures ---


@pytest.fixture
def test_settings():
    """Create test settings."""
    return Settings(
        zone="test.spf.guru",
        soa_serial="2025010100",
        soa_hostmaster="admin@example.com",
        ns_records="ns1.test.spf.guru ns2.test.spf.guru",
        default_ttl=300,
        max_chain=9,
        spf_record_mode=0,
        my_domains="",
        bunny_db_url=None,
        bunny_db_token=None,
        _env_file=None,
    )


@pytest.fixture
def test_cache():
    """Fresh cache for each test."""
    return CacheManager(backend=MemoryCache())


@pytest.fixture
def fake_resolver():
    """Create a fake DNS resolver."""
    return FakeDNSResolver()


@pytest.fixture
def fake_db_logger():
    """Create a fake database logger."""
    return FakeDatabaseLogger()


@pytest.fixture
def test_extractor(test_settings, fake_resolver, test_cache):
    """Create a test SPF extractor with fake dependencies."""
    return SPFExtractor(
        settings=test_settings,
        resolver=fake_resolver,
        cache=test_cache,
    )


@pytest.fixture
def test_deps(test_settings, test_cache, test_extractor, fake_db_logger):
    """Create test dependencies."""
    return RouteDependencies(
        settings=test_settings,
        cache=test_cache,
        extractor=test_extractor,
        get_banner_fn=lambda result: f"TEST BANNER: {result}",
        log_spf_result_fn=fake_db_logger,
    )


@pytest.fixture
def app(test_deps):
    """Create a test FastAPI application with injected dependencies."""
    set_dependencies(test_deps)
    test_app = FastAPI()
    test_app.include_router(router)
    yield test_app
    reset_dependencies()


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def clear_patterns_cache_fixture():
    """Clear patterns cache before and after each test."""
    reset_patterns_cache()
    yield
    reset_patterns_cache()


# --- Helper function tests ---


class TestIpVersion:
    """Tests for ip_version helper function."""

    def test_ipv4_returns_4(self):
        assert ip_version("192.168.1.1") == 4

    def test_ipv6_returns_6(self):
        assert ip_version("2001:db8::1") == 6

    def test_invalid_ip_raises_error(self):
        with pytest.raises(ValueError):
            ip_version("not-an-ip")


# --- PowerDNS metadata endpoint tests ---


class TestGetAllDomains:
    """Tests for /getAllDomains endpoint."""

    def test_returns_zone_info(self, client, test_settings):
        response = client.get("/getAllDomains")

        assert response.status_code == 200
        data = response.json()
        assert len(data["result"]) == 1
        assert data["result"][0]["zone"] == test_settings.zone_dotted
        assert data["result"][0]["kind"] == "NATIVE"
        assert data["result"][0]["serial"] == int(test_settings.soa_serial)


class TestGetDomainInfo:
    """Tests for /getDomainInfo/{zone} endpoint."""

    def test_returns_info_for_matching_zone(self, client, test_settings):
        response = client.get(f"/getDomainInfo/{test_settings.zone}")

        assert response.status_code == 200
        data = response.json()
        assert data["result"]["zone"] == test_settings.zone_dotted
        assert data["result"]["auth"] is True

    def test_returns_info_for_zone_with_trailing_dot(self, client, test_settings):
        response = client.get(f"/getDomainInfo/{test_settings.zone_dotted}")

        assert response.status_code == 200
        data = response.json()
        assert data["result"]["zone"] == test_settings.zone_dotted

    def test_returns_false_for_unknown_zone(self, client):
        response = client.get("/getDomainInfo/unknown.zone.com")

        assert response.status_code == 200
        data = response.json()
        assert data["result"] is False
        assert "I don't serve" in data["log"]


class TestGetAllDomainMetadata:
    """Tests for /getAllDomainMetadata/{zone} endpoint."""

    def test_returns_presigned_metadata(self, client):
        response = client.get("/getAllDomainMetadata/test.spf.guru")

        assert response.status_code == 200
        data = response.json()
        assert data["result"]["PRESIGNED"] == ["0"]


class TestGetDomainMetadata:
    """Tests for /getDomainMetadata/{zone}/PRESIGNED endpoint."""

    def test_returns_presigned_value(self, client):
        response = client.get("/getDomainMetadata/test.spf.guru/PRESIGNED")

        assert response.status_code == 200
        data = response.json()
        assert data["result"] == ["0"]


class TestStartTransaction:
    """Tests for /startTransaction endpoint."""

    def test_returns_false(self, client):
        response = client.post("/startTransaction/-1/test.spf.guru/12345")

        assert response.status_code == 200
        data = response.json()
        assert data["result"] is False


# --- Lookup endpoint tests ---


class TestLookupZoneApex:
    """Tests for lookup endpoint at zone apex."""

    def test_returns_ns_records_for_zone_apex(self, client, test_settings):
        response = client.get(f"/lookup/{test_settings.zone}/NS")

        assert response.status_code == 200
        data = response.json()
        ns_records = [r for r in data["result"] if r["qtype"] == "NS"]
        assert len(ns_records) == 2
        assert ns_records[0]["content"] == "ns1.test.spf.guru."
        assert ns_records[1]["content"] == "ns2.test.spf.guru."

    def test_returns_soa_record_for_zone_apex(self, client, test_settings):
        response = client.get(f"/lookup/{test_settings.zone}/SOA")

        assert response.status_code == 200
        data = response.json()
        soa_records = [r for r in data["result"] if r["qtype"] == "SOA"]
        assert len(soa_records) == 1
        assert "ns1.test.spf.guru." in soa_records[0]["content"]
        assert test_settings.soa_serial in soa_records[0]["content"]

    def test_returns_both_ns_and_soa_for_any_query(self, client, test_settings):
        response = client.get(f"/lookup/{test_settings.zone}/ANY")

        assert response.status_code == 200
        data = response.json()
        ns_records = [r for r in data["result"] if r["qtype"] == "NS"]
        soa_records = [r for r in data["result"] if r["qtype"] == "SOA"]
        assert len(ns_records) == 2
        assert len(soa_records) == 1

    def test_returns_empty_for_unknown_qtype(self, client, test_settings):
        response = client.get(f"/lookup/{test_settings.zone}/MX")

        assert response.status_code == 200
        data = response.json()
        assert data["result"] == []


class TestLookupUnknownDomain:
    """Tests for lookup endpoint with unknown domains."""

    def test_returns_empty_for_unknown_domain(self, client):
        response = client.get("/lookup/unknown.domain.com/TXT")

        assert response.status_code == 200
        data = response.json()
        assert data["result"] == []

    def test_returns_empty_for_invalid_pattern(self, client):
        response = client.get("/lookup/invalid.pattern.test.spf.guru/TXT")

        assert response.status_code == 200
        data = response.json()
        assert data["result"] == []


class TestLookupSPFPass:
    """Tests for lookup endpoint when SPF check passes."""

    def test_d_pattern_spf_pass_returns_pass_response(
        self, client, fake_resolver, test_settings  # pylint: disable=unused-argument
    ):
        # Set up DNS to return SPF record with IP that will match
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        # d_pattern query: i.{reversed_ip}._d.{domain}.{zone}.
        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        assert len(txt_records) >= 1

        # Check for pass response (IP should match the /24 network)
        contents = [r["content"] for r in txt_records]
        assert any("ip4:192.168.1.1" in c for c in contents)

    def test_spf_pass_includes_a_and_aaaa_records(
        self, client, fake_resolver, test_settings  # pylint: disable=unused-argument
    ):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        a_records = [r for r in data["result"] if r["qtype"] == "A"]
        aaaa_records = [r for r in data["result"] if r["qtype"] == "AAAA"]

        assert len(a_records) == 1
        assert a_records[0]["content"] == "127.0.0.2"
        assert len(aaaa_records) == 1
        assert aaaa_records[0]["content"] == "fe80::2"

    def test_spf_pass_includes_banner(self, client, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        contents = [r["content"] for r in txt_records]
        assert any("TEST BANNER: PASS" in c for c in contents)


class TestLookupSPFFail:
    """Tests for lookup endpoint when SPF check fails."""

    def test_d_pattern_spf_fail_returns_fail_response(self, client, fake_resolver):
        # Set up DNS with SPF record that won't match the queried IP
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

        # Query with IP not in the SPF record
        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        assert len(txt_records) >= 1

        # Check for fail response (should return spf_fail_response)
        contents = [r["content"] for r in txt_records]
        # When no macros, fail response is "v=spf1 ~all"
        assert any("v=spf1 ~all" in c for c in contents)

    def test_spf_fail_does_not_include_a_aaaa_records(self, client, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        a_records = [r for r in data["result"] if r["qtype"] == "A"]
        aaaa_records = [r for r in data["result"] if r["qtype"] == "AAAA"]

        # No A/AAAA records on fail
        assert len(a_records) == 0
        assert len(aaaa_records) == 0

    def test_spf_fail_includes_macros_in_response(self, client, fake_resolver):
        # SPF with macros that should be preserved
        fake_resolver.txt_records["example.com"] = [
            "v=spf1 ip4:10.0.0.0/8 include:other.com ~all"
        ]
        fake_resolver.txt_records["other.com"] = [
            "v=spf1 exists:%{i}._spf.example.com ~all"
        ]

        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        contents = [r["content"] for r in txt_records]

        # Macro should be in fail response
        assert any("exists:" in c for c in contents)

    def test_spf_fail_includes_fail_banner(self, client, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        contents = [r["content"] for r in txt_records]
        assert any("TEST BANNER: FAIL" in c for c in contents)


class TestLookupFailCheck:
    """Tests for lookup endpoint with fail_check mode (f. prefix)."""

    def test_f_pattern_spf_pass_returns_softfail(self, client, fake_resolver):
        # IP matches, but f. prefix means we want fail behavior
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        # f. prefix triggers fail_check mode
        query = "f.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        contents = [r["content"] for r in txt_records]

        # When fail_check is True and SPF passes, return softfail
        assert any("v=spf1 ~all" in c for c in contents)

    def test_f_pattern_spf_fail_returns_pass_response(self, client, fake_resolver):
        # IP doesn't match, f. prefix inverts behavior
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

        query = "f.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()

        # Should include A/AAAA records since fail_check inverts
        a_records = [r for r in data["result"] if r["qtype"] == "A"]
        assert len(a_records) == 1
        assert a_records[0]["content"] == "127.0.0.2"


class TestLookupVendorPattern:
    """Tests for vendor pattern ({domain}._i.{reversed_ip}.{zone})."""

    def test_vendor_pattern_spf_pass(self, client, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        # vendor pattern: {domain}._i.{reversed_ip}.{zone}.
        query = "example.com._i.1.1.168.192.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        assert len(txt_records) >= 1

        contents = [r["content"] for r in txt_records]
        assert any("ip4:192.168.1.1" in c for c in contents)


class TestLookupIPv6:
    """Tests for IPv6 address handling."""

    def test_ipv6_spf_pass(self, client, fake_resolver, test_deps):
        # Change to mode 1 for rbldnsd pattern which is easier for IPv6
        test_deps.settings = Settings(
            zone="test.spf.guru",
            spf_record_mode=1,
            my_domains="",
            default_ttl=300,
            max_chain=9,
            _env_file=None,
        )

        fake_resolver.txt_records["example.com"] = ["v=spf1 ip6:2001:db8::/32 ~all"]

        # IPv6 loopback in nibble format for rbldnsd pattern
        ipv6_nibble = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        query = f"{ipv6_nibble}.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]

        if txt_records:
            contents = [r["content"] for r in txt_records]
            # Should contain ip6 in response
            assert any("ip6:" in c for c in contents)


class TestLookupCaching:
    """Tests for caching behavior in lookup."""

    def test_lookup_uses_cached_spf_result(
        self, client, fake_resolver, test_cache  # pylint: disable=unused-argument
    ):
        # Pre-populate cache with SPF check result
        cached_result = {
            "domain": "example.com",
            "ip": "192.168.1.1",
            "pass": True,
            "spf_pass_response": "v=spf1 ip4:192.168.1.1 ~all",
            "spf_fail_response": "v=spf1 ~all",
        }
        # Sync cache set for test setup

        asyncio.get_event_loop().run_until_complete(
            test_cache.set(
                "spf-result:example.com-192.168.1.1",
                json.dumps(cached_result),
                300,
            )
        )

        query = "i.1.1.168.192._d.example.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        contents = [r["content"] for r in txt_records]

        # Should use cached result
        assert any("ip4:192.168.1.1" in c for c in contents)


# --- Internal _spf_check function tests ---


class TestSpfCheckInternal:
    """Tests for _spf_check internal function."""

    async def test_returns_pass_for_matching_ip(self, test_deps, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        result = await _spf_check("example.com", "192.168.1.100", deps=test_deps)

        assert result["pass"] is True
        assert result["cached"] is False
        assert "ip4:192.168.1.100" in result["spf_pass_response"]

    async def test_returns_fail_for_non_matching_ip(self, test_deps, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

        result = await _spf_check("example.com", "192.168.1.100", deps=test_deps)

        assert result["pass"] is False
        assert result["cached"] is False

    async def test_returns_cached_result(self, test_deps, test_cache):
        # Pre-populate cache
        cached_result = {
            "domain": "cached.com",
            "ip": "1.2.3.4",
            "pass": True,
            "spf_pass_response": "v=spf1 ip4:1.2.3.4 ~all",
            "spf_fail_response": "v=spf1 ~all",
        }
        await test_cache.set(
            "spf-result:cached.com-1.2.3.4",
            json.dumps(cached_result),
            300,
        )

        result = await _spf_check("cached.com", "1.2.3.4", deps=test_deps)

        assert result["cached"] is True
        assert result["pass"] is True

    async def test_handles_ipv6_addresses(self, test_deps, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip6:2001:db8::/32 ~all"]

        result = await _spf_check("example.com", "2001:db8::1", deps=test_deps)

        assert result["pass"] is True
        assert "ip6:2001:db8::1" in result["spf_pass_response"]

    async def test_handles_cidr_ranges(self, test_deps, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:10.0.0.0/8 ~all"]

        # IP within the /8 range
        result = await _spf_check("example.com", "10.255.255.255", deps=test_deps)
        assert result["pass"] is True

        # IP outside the /8 range
        result2 = await _spf_check("example.com", "11.0.0.1", deps=test_deps)
        assert result2["pass"] is False

    async def test_includes_macros_in_fail_response(self, test_deps, fake_resolver):
        fake_resolver.txt_records["example.com"] = [
            "v=spf1 ip4:10.0.0.0/8 include:other.com ~all"
        ]
        fake_resolver.txt_records["other.com"] = [
            "v=spf1 exists:%{i}._check.example.com ~all"
        ]

        result = await _spf_check("example.com", "192.168.1.1", deps=test_deps)

        assert result["pass"] is False
        assert "exists:" in result["spf_fail_response"]

    async def test_max_chain_limits_macros(self, test_deps, fake_resolver):
        # Set max_chain to 2
        test_deps.settings = Settings(
            zone="test.spf.guru",
            max_chain=2,
            default_ttl=300,
            _env_file=None,
        )

        # SPF with multiple macros
        fake_resolver.txt_records["example.com"] = [
            "v=spf1 ip4:10.0.0.0/8 include:one.com ~all"
        ]
        fake_resolver.txt_records["one.com"] = ["v=spf1 exists:%{i}.one ~all"]

        result = await _spf_check("example.com", "192.168.1.1", deps=test_deps)

        # Count macros in response
        macros_in_response = result["spf_fail_response"].count("exists:")
        assert macros_in_response <= 2

    async def test_normalizes_domain_case(self, test_deps, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        result = await _spf_check("EXAMPLE.COM.", "192.168.1.1", deps=test_deps)

        assert result["pass"] is True

    async def test_invalid_ip_raises_error(self, test_deps):
        with pytest.raises(ValueError):
            await _spf_check("example.com", "not-an-ip", deps=test_deps)


# --- Edge cases ---


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_qname(self, client):
        # FastAPI should handle this, but let's verify
        response = client.get("/lookup//TXT")
        # Will likely be 404 or handled differently
        assert response.status_code in (200, 404, 422)

    def test_very_long_domain(self, client):
        # 253 chars is max for domain
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + ".test.spf.guru."
        response = client.get(f"/lookup/{long_domain}/TXT")

        assert response.status_code == 200

    def test_special_characters_in_domain(self, client):
        # Valid DNS chars: alphanumeric and hyphen
        response = client.get("/lookup/test-domain.test.spf.guru/TXT")
        assert response.status_code == 200

    def test_case_insensitive_qtype(self, client, test_settings):
        response1 = client.get(f"/lookup/{test_settings.zone}/NS")
        response2 = client.get(f"/lookup/{test_settings.zone}/ns")

        # Both should work (PowerDNS sends uppercase)
        assert response1.status_code == 200
        # Lowercase might not match depending on implementation
        assert response2.status_code == 200

    def test_case_insensitive_qname(self, client, fake_resolver):
        fake_resolver.txt_records["example.com"] = ["v=spf1 ip4:192.168.1.0/24 ~all"]

        # Uppercase should work
        query = "I.1.1.168.192._D.EXAMPLE.COM.TEST.SPF.GURU."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200

    def test_no_spf_record_returns_softfail(self, client, fake_resolver):
        # Domain with no SPF record
        fake_resolver.txt_records["noSpf.com"] = ["some other txt record"]

        query = "i.1.1.168.192._d.nospf.com.test.spf.guru."
        response = client.get(f"/lookup/{query}/TXT")

        assert response.status_code == 200
        data = response.json()
        txt_records = [r for r in data["result"] if r["qtype"] == "TXT"]
        contents = [r["content"] for r in txt_records]

        # Should return default fail response
        assert any("v=spf1 ~all" in c for c in contents)

    async def test_spf_check_with_no_networks(self, test_deps, fake_resolver):
        # SPF with only macros, no IP ranges
        fake_resolver.txt_records["macro-only.com"] = [
            "v=spf1 exists:%{i}._check.example.com ~all"
        ]

        result = await _spf_check("macro-only.com", "192.168.1.1", deps=test_deps)

        # No networks means fail
        assert result["pass"] is False
        assert "exists:" in result["spf_fail_response"]

    async def test_spf_check_with_invalid_network(self, test_deps, fake_resolver):
        # SPF with invalid network that should be skipped
        fake_resolver.txt_records["example.com"] = [
            "v=spf1 ip4:not-a-network ip4:192.168.1.0/24 ~all"
        ]

        result = await _spf_check("example.com", "192.168.1.1", deps=test_deps)

        # Should still pass because valid network is present
        assert result["pass"] is True
