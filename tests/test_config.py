"""Tests for core/config.py."""

# pylint: disable=missing-function-docstring

from spf_guru.core.config import Settings, _ensure_dot


class TestEnsureDot:
    """Tests for _ensure_dot helper function."""

    def test_adds_dot_when_missing(self):
        assert _ensure_dot("example.com") == "example.com."

    def test_preserves_existing_dot(self):
        assert _ensure_dot("example.com.") == "example.com."

    def test_strips_whitespace(self):
        assert _ensure_dot("  example.com  ") == "example.com."

    def test_empty_string(self):
        assert _ensure_dot("") == "."


class TestSettings:
    """Tests for Settings class."""

    def test_default_values(self, monkeypatch):
        # Clear env vars that conftest sets, to test actual defaults
        monkeypatch.delenv("ZONE", raising=False)
        monkeypatch.delenv("SOA_SERIAL", raising=False)
        monkeypatch.delenv("SOA_HOSTMASTER", raising=False)
        monkeypatch.delenv("NS_RECORDS", raising=False)

        settings = Settings(_env_file=None)
        assert settings.zone == "my.spf.guru"
        assert settings.redis_port == 6379
        assert settings.default_ttl == 14400
        assert settings.max_chain == 9

    def test_zone_dotted(self):
        settings = Settings(zone="test.spf.guru")
        assert settings.zone_dotted == "test.spf.guru."

    def test_zone_dotted_already_has_dot(self):
        settings = Settings(zone="test.spf.guru.")
        assert settings.zone_dotted == "test.spf.guru."

    def test_soa_hostmaster_dotted(self):
        settings = Settings(soa_hostmaster="admin@example.com")
        assert settings.soa_hostmaster_dotted == "admin.example.com."

    def test_ns_records_list_empty(self):
        settings = Settings(zone="my.spf.guru", ns_records="")
        # Should return default based on zone
        assert settings.ns_records_list == ["ns-my.spf.guru."]

    def test_ns_records_list_with_values(self):
        settings = Settings(ns_records="ns1.example.com ns2.example.com")
        assert settings.ns_records_list == ["ns1.example.com.", "ns2.example.com."]

    def test_primary_ns(self):
        settings = Settings(ns_records="ns1.example.com ns2.example.com")
        assert settings.primary_ns == "ns1.example.com."

    def test_my_domains_set_empty(self):
        settings = Settings(my_domains="")
        assert settings.my_domains_set == set()

    def test_my_domains_set_with_values(self):
        settings = Settings(my_domains="example.com test.org")
        assert settings.my_domains_set == {"example.com", "test.org"}

    def test_my_domains_set_lowercased(self):
        settings = Settings(my_domains="Example.COM Test.ORG")
        assert settings.my_domains_set == {"example.com", "test.org"}

    def test_use_redis_false_when_no_ip(self):
        settings = Settings(redis_ip=None)
        assert settings.use_redis is False

    def test_use_redis_true_when_ip_set(self):
        settings = Settings(redis_ip="127.0.0.1")
        assert settings.use_redis is True

    def test_redis_url(self):
        settings = Settings(redis_ip="192.168.1.1", redis_port=6380)
        assert settings.redis_url == "redis://192.168.1.1:6380/0"

    def test_special_spf_record_default(self):
        settings = Settings(zone="my.spf.guru", spf_macro_record=None)
        assert settings.special_spf_record == "i.%{ir}._d.%{d}.my.spf.guru."

    def test_special_spf_record_custom(self):
        settings = Settings(spf_macro_record="custom.%{d}.record")
        assert settings.special_spf_record == "custom.%{d}.record"

    def test_fail_spf_record(self):
        settings = Settings(zone="my.spf.guru")
        assert settings.fail_spf_record == "f.%{ir}._d.%{d}.my.spf.guru."
