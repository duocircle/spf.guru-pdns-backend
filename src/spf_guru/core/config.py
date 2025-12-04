"""Centralized configuration using Pydantic BaseSettings."""

from functools import lru_cache
from typing import Optional, Set

from pydantic_settings import BaseSettings, SettingsConfigDict


def _ensure_dot(s: str) -> str:
    """Ensure string ends with a dot (for DNS names)."""
    s = s.strip()

    if not s.endswith("."):
        s += "."

    return s


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Redis configuration
    redis_ip: Optional[str] = None
    redis_port: int = 6379
    redis_db: int = 0

    # DNS zone configuration
    zone: str = "my.spf.guru"
    soa_serial: str = "2025120400"
    soa_hostmaster: str = "hostmaster@duocircle.com"
    ns_records: str = ""  # Space-separated list of NS records

    # Domain control list (whitelist)
    my_domains: str = ""  # Space-separated list of allowed domains (fallback)

    # SPF configuration
    source_prefix: Optional[str] = None
    spf_record_mode: int = 0  # 0=standard, 1=rbldnsd
    spf_macro_record: Optional[str] = None

    # Database logging (optional)
    bunny_db_url: Optional[str] = None
    bunny_db_token: Optional[str] = None

    # Sentry configuration (optional)
    sentry_dsn: Optional[str] = None
    sentry_environment: str = "production"
    sentry_traces_sample_rate: float = 1.0

    # SPF processing constants
    spf_prefix: str = "v=spf1"
    spf_suffix: str = " ~all"
    max_chain: int = 9
    default_ttl: int = 14400

    @property
    def zone_dotted(self) -> str:
        """Return zone with trailing dot."""
        return _ensure_dot(self.zone)

    @property
    def soa_hostmaster_dotted(self) -> str:
        """Return SOA hostmaster formatted for DNS (@ replaced with .)."""
        hostmaster = self.soa_hostmaster.replace("@", ".")

        return _ensure_dot(hostmaster)

    @property
    def ns_records_list(self) -> list[str]:
        """Return NS records as a list with trailing dots."""
        if not self.ns_records.strip():
            # Default NS record based on zone
            return [_ensure_dot(f"ns-{self.zone}")]

        return [_ensure_dot(ns) for ns in self.ns_records.lower().split()]

    @property
    def primary_ns(self) -> str:
        """Return the primary NS record."""
        return self.ns_records_list[0]

    @property
    def my_domains_set(self) -> Set[str]:
        """Return allowed domains as a set."""
        if not self.my_domains.strip():
            return set()

        return set(self.my_domains.lower().split())

    @property
    def special_spf_record(self) -> str:
        """Return the SPF macro record template."""
        if self.spf_macro_record:
            return self.spf_macro_record

        return f"i.%{{ir}}._d.%{{d}}.{self.zone_dotted}"

    @property
    def fail_spf_record(self) -> str:
        """Return the fail SPF macro record template."""
        return f"f.%{{ir}}._d.%{{d}}.{self.zone_dotted}"

    @property
    def use_redis(self) -> bool:
        """Check if Redis is configured."""
        return self.redis_ip is not None

    @property
    def redis_url(self) -> str:
        """Return Redis connection URL."""
        return f"redis://{self.redis_ip}:{self.redis_port}/{self.redis_db}"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
