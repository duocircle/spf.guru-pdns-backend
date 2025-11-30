"""Tests for dns/patterns.py."""

# pylint: disable=missing-function-docstring,redefined-outer-name

import pytest

from spf_guru.core.config import Settings
from spf_guru.dns.patterns import (
    UNAUTH_SENTINEL,
    dot2std,
    dot_count,
    extract_info,
    is_ipv4,
    is_ipv6,
    reset_patterns_cache,
    return_ns,
    return_soa,
    reverse_ip,
    sanitize_spf_record,
)


@pytest.fixture
def test_settings():
    """Create test settings without reading from env."""
    return Settings(
        zone="my.spf.guru",
        soa_serial="2025010100",
        soa_hostmaster="admin@example.com",
        ns_records="ns1.example.com ns2.example.com",
        spf_record_mode=0,
        my_domains="",
        _env_file=None,
    )


@pytest.fixture(autouse=True)
def clear_patterns_cache():
    """Clear patterns cache before and after each test."""
    reset_patterns_cache()
    yield
    reset_patterns_cache()


class TestDot2Std:
    """Tests for dot2std IPv6 nibble conversion."""

    def test_valid_ipv6_nibble_format(self):
        # Loopback address ::1 in nibble format (reversed)
        nibble = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        result = dot2std(nibble)
        assert result == "::1"

    def test_ipv6_with_ip6_arpa_suffix(self):
        nibble = (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
        )
        result = dot2std(nibble)
        assert result == "::1"

    def test_invalid_length_raises_error(self):
        with pytest.raises(ValueError, match="32 dot-separated"):
            dot2std("1.0.0.0")

    def test_invalid_hex_nibble_raises_error(self):
        # 'g' is not a valid hex character
        nibble = "g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        with pytest.raises(ValueError, match="Invalid hex nibble"):
            dot2std(nibble)


class TestDotCount:
    """Tests for dot_count IP version detection."""

    def test_ipv4_returns_4(self):
        assert dot_count("192.168.1.1") == 4

    def test_ipv6_nibble_returns_6(self):
        nibble = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        assert dot_count(nibble) == 6

    def test_invalid_format_returns_0(self):
        assert dot_count("invalid") == 0
        assert dot_count("192.168.1") == 0  # Incomplete IPv4


class TestIsIpv4:
    """Tests for is_ipv4 validation."""

    def test_valid_ipv4_returns_reversed(self):
        result = is_ipv4("192.168.1.1")
        assert result == "1.1.168.192"

    def test_invalid_ipv4_returns_false(self):
        assert is_ipv4("invalid") is False
        assert is_ipv4("192.168.1") is False
        assert is_ipv4("256.1.1.1") is False


class TestIsIpv6:
    """Tests for is_ipv6 validation."""

    def test_valid_ipv6_nibble_returns_standard(self):
        nibble = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        result = is_ipv6(nibble)
        assert result == "::1"

    def test_invalid_ipv6_returns_false(self):
        assert is_ipv6("invalid") is False
        assert is_ipv6("192.168.1.1") is False  # IPv4, not IPv6 nibble


class TestReverseIp:
    """Tests for reverse_ip function."""

    def test_reverses_ipv4(self):
        assert reverse_ip("192.168.1.1") == "1.1.168.192"

    def test_reverses_simple_ip(self):
        assert reverse_ip("1.2.3.4") == "4.3.2.1"


class TestSanitizeSpfRecord:
    """Tests for sanitize_spf_record function."""

    def test_returns_unauth_sentinel_when_no_match(self, test_settings):
        result = sanitize_spf_record("v=spf1 ip4:1.2.3.4 ~all", settings=test_settings)
        assert result == UNAUTH_SENTINEL

    def test_removes_special_spf_tokens(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_macro_record="special.record",
            _env_file=None,
        )

        result = sanitize_spf_record(
            "v=spf1 include:special.record ip4:1.2.3.4 ~all",
            settings=settings,
        )
        assert "include:special.record" not in result
        assert "ip4:1.2.3.4" in result


class TestReturnSoa:
    """Tests for return_soa function."""

    def test_returns_soa_record(self, test_settings):
        result = return_soa("example.com.", settings=test_settings)

        assert len(result) == 1
        record = result[0]
        assert record["qname"] == "example.com."
        assert record["qtype"] == "SOA"
        assert "ns1.example.com." in record["content"]
        assert "admin.example.com." in record["content"]
        assert "2025010100" in record["content"]
        assert record["ttl"] == 3600
        assert record["auth"] is True

    def test_auth_can_be_disabled(self, test_settings):
        result = return_soa("example.com.", auth=False, settings=test_settings)
        assert result[0]["auth"] is False


class TestReturnNs:
    """Tests for return_ns function."""

    def test_returns_ns_records(self, test_settings):
        result = return_ns("example.com", settings=test_settings)

        assert len(result) == 2
        assert result[0]["qtype"] == "NS"
        assert result[0]["content"] == "ns1.example.com."
        assert result[1]["content"] == "ns2.example.com."

    def test_lowercases_qname(self, test_settings):
        result = return_ns("EXAMPLE.COM", settings=test_settings)
        assert result[0]["qname"] == "example.com."


class TestExtractInfo:
    """Tests for extract_info pattern matching."""

    async def test_empty_string_returns_false(self, test_settings):
        result = await extract_info("", settings=test_settings)
        assert result is False

    async def test_d_pattern_mode_0(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=0,
            my_domains="",
            _env_file=None,
        )

        # d_pattern: i.{reversed_ip}._d.{domain}.my.spf.guru.
        query = "i.1.1.168.192._d.example.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is not False
        assert result["ip_address"] == "192.168.1.1"
        assert result["domain"] == "example.com"
        assert result["ip_version"] == 4
        assert result["fail_check"] is False

    async def test_d_pattern_with_fail_check(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=0,
            my_domains="",
            _env_file=None,
        )

        # f. prefix triggers fail_check
        query = "f.1.1.168.192._d.example.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is not False
        assert result["fail_check"] is True

    async def test_rbldnsd_pattern_mode_1(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=1,
            my_domains="",
            _env_file=None,
        )

        # rbldnsd pattern: {reversed_ip}.{domain}.my.spf.guru.
        query = "1.1.168.192.example.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is not False
        assert result["ip_address"] == "192.168.1.1"
        assert result["domain"] == "example.com"
        assert result["ip_version"] == 4

    async def test_vendor_pattern_mode_0(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=0,
            my_domains="",
            _env_file=None,
        )

        # vendor pattern: {domain}._i.{reversed_ip}.my.spf.guru.
        query = "example.com._i.1.1.168.192.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is not False
        assert result["ip_address"] == "192.168.1.1"
        assert result["domain"] == "example.com."

    async def test_domain_control_list_blocks_unauthorized(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=1,
            my_domains="allowed.com",
            _env_file=None,
        )

        query = "1.1.168.192.notallowed.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        # Should return False because domain is not in allowed list
        assert result is False

    async def test_domain_control_list_allows_authorized(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=1,
            my_domains="allowed.com",
            _env_file=None,
        )

        query = "1.1.168.192.allowed.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is not False
        assert result["domain"] == "allowed.com"

    async def test_ipv6_nibble_format(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=1,
            my_domains="",
            _env_file=None,
        )

        # IPv6 loopback in nibble format
        ipv6_nibble = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        query = f"{ipv6_nibble}.example.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is not False
        assert result["ip_address"] == "::1"
        assert result["ip_version"] == 6

    async def test_mode_0_rejects_rbldnsd_pattern(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=0,  # Mode 0 doesn't use rbldnsd pattern
            my_domains="",
            _env_file=None,
        )

        # This is rbldnsd format, should not match in mode 0
        query = "1.1.168.192.example.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is False

    async def test_mode_1_rejects_d_pattern(self):
        settings = Settings(
            zone="my.spf.guru",
            spf_record_mode=1,  # Mode 1 only uses rbldnsd pattern
            my_domains="",
            _env_file=None,
        )

        # This is d_pattern format, should not match in mode 1
        query = "i.1.1.168.192._d.example.com.my.spf.guru."
        result = await extract_info(query, settings=settings)

        assert result is False
