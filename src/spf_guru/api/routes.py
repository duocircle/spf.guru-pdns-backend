"""API routes for the SPF Guru service."""

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

import dns.name
from fastapi import APIRouter, Depends

from spf_guru.core.cache import CacheManager, get_cache_manager
from spf_guru.core.config import Settings, get_settings
from spf_guru.core.database import log_spf_result
from spf_guru.core.extractor import SPFExtractor, get_extractor
from spf_guru.dns.patterns import extract_info, return_ns, return_soa
from spf_guru.utils.banners import get_banner
from spf_guru.utils.decorators import sentry_exception_catcher
from spf_guru.utils.exceptions import (
    DatabaseError,
    PatternMatchError,
    capture_exception,
)

router = APIRouter()


class DatabaseLogger(Protocol):
    """Protocol for database logging."""

    async def __call__(
        self, domain: str, ip: str, result: str, ipversion: int
    ) -> bool: ...


@dataclass
class RouteDependencies:
    """Dependencies for route handlers."""

    settings: Settings = field(default_factory=get_settings)
    cache: CacheManager = field(default_factory=get_cache_manager)
    extractor: SPFExtractor = field(default_factory=get_extractor)
    get_banner_fn: Callable[[str], str] = get_banner
    log_spf_result_fn: Optional[DatabaseLogger] = None

    def __post_init__(self):
        if self.log_spf_result_fn is None:
            self.log_spf_result_fn = log_spf_result


# Global dependencies instance (can be overridden for testing)
_dependencies: Optional[RouteDependencies] = None


def get_dependencies() -> RouteDependencies:
    """Get the current route dependencies."""
    global _dependencies  # pylint: disable=global-statement
    if _dependencies is None:
        _dependencies = RouteDependencies()
    return _dependencies


def set_dependencies(deps: RouteDependencies) -> None:
    """Set custom dependencies (useful for testing)."""
    global _dependencies  # pylint: disable=global-statement
    _dependencies = deps


def reset_dependencies() -> None:
    """Reset dependencies to default (useful for testing)."""
    global _dependencies  # pylint: disable=global-statement
    _dependencies = None


def ip_version(addr: str) -> int:
    """Get IP version (4 or 6) from address string."""
    return ipaddress.ip_address(addr).version


async def _spf_check(
    domain: str,
    ip_address: str,
    deps: Optional[RouteDependencies] = None,
) -> dict:
    """Internal SPF check logic."""
    if deps is None:
        deps = get_dependencies()

    settings = deps.settings
    cache = deps.cache
    extractor = deps.extractor

    # Try cache
    cache_key = f"spf-result:{domain}-{ip_address}"

    if cached := await cache.get(cache_key):
        result = json.loads(cached)
        result["cached"] = True
        return result

    # Get SPF data
    spf_data = await extractor.get_or_compute_spf(domain.rstrip(".").lower())

    ips = spf_data["ips"]
    macros = spf_data.get("macro_records", [])

    # Validate IP
    ip_obj = ipaddress.ip_address(ip_address)

    # Check membership
    networks = []

    for net in ips:
        try:
            networks.append(ipaddress.ip_network(net, strict=False))
        except ValueError:
            continue

    allowed = any(ip_obj in n for n in networks)

    # Build response
    resp = {"domain": domain, "ip": ip_address, "pass": allowed}
    resp["spf_pass_response"] = f"v=spf1 ip{ip_version(ip_address)}:{ip_address} ~all"

    if len(macros) > 0:
        resp["spf_fail_response"] = (
            "v=spf1 " + " ".join(macros[: settings.max_chain]) + " ~all"
        )
    else:
        resp["spf_fail_response"] = "v=spf1 ~all"

    # Cache result
    await cache.set(cache_key, json.dumps(resp), settings.default_ttl, log=False)

    # Log to database if configured (non-critical, don't fail request)
    result_label = "pass" if allowed else "fail"

    if settings.bunny_db_url and settings.bunny_db_token and deps.log_spf_result_fn:
        try:
            await deps.log_spf_result_fn(
                domain, ip_address, result_label, ip_version(ip_address)
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            # Database logging is non-critical, capture but don't fail
            capture_exception(
                DatabaseError(f"Failed to log SPF result: {e}"),
                {"domain": domain, "ip": ip_address, "result": result_label},
                level="warning",
            )

    resp["cached"] = False

    return resp


@router.get("/lookup/{qname}/{qtype}")
@sentry_exception_catcher
async def lookup(
    qname: str,
    qtype: str,
    deps: RouteDependencies = Depends(get_dependencies),
):
    """PowerDNS remote backend lookup endpoint."""
    settings = deps.settings
    zone = settings.zone_dotted
    qname = qname.lower()

    try:
        info = await extract_info(qname, settings=settings)
    except ValueError:
        # Invalid input format - expected, not an error
        info = False
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Unexpected error in pattern matching - report to Sentry
        capture_exception(
            PatternMatchError(f"Pattern extraction failed: {e}"),
            {"qname": qname, "qtype": qtype},
        )
        info = False

    responses = []

    if info is False:
        if zone.lower().rstrip(".") == qname.lower().rstrip("."):
            if qtype in ("ANY", "NS"):
                responses.extend(return_ns(zone, settings=settings))
            if qtype in ("ANY", "SOA"):
                responses.extend(return_soa(zone, settings=settings))

        return {"result": responses}

    z = dns.name.from_text(zone)
    n = dns.name.from_text(qname)
    query = n - z
    querystring = query.to_text()

    if info is not False and querystring != "@" and qtype in ("TXT", "ANY"):
        if len(settings.my_domains_set) > 0 and settings.source_prefix:
            domain_part = settings.source_prefix + "." + info["domain"]
        else:
            domain_part = info["domain"]

        ip_part = info["ip_address"]
        check_for_fail = info["fail_check"]

        try:
            spf_output = await _spf_check(domain_part, ip_part, deps=deps)
        except ValueError as e:
            # Invalid IP address format - expected user error
            capture_exception(
                e, {"domain": domain_part, "ip": ip_part}, level="warning"
            )
            return {"result": responses}
        except Exception as e:  # pylint: disable=broad-exception-caught
            # Unexpected error - report to Sentry and return empty
            capture_exception(e, {"domain": domain_part, "ip": ip_part})
            return {"result": responses}

        if spf_output["pass"]:
            response_banner = deps.get_banner_fn("PASS")
        else:
            response_banner = deps.get_banner_fn("FAIL")

        if check_for_fail:
            if not spf_output["pass"]:
                content = spf_output["spf_pass_response"]
                responses.append(
                    {
                        "qname": qname,
                        "qtype": "A",
                        "content": "127.0.0.2",
                        "ttl": settings.default_ttl,
                        "auth": True,
                    }
                )
                responses.append(
                    {
                        "qname": qname,
                        "qtype": "AAAA",
                        "content": "fe80::2",
                        "ttl": settings.default_ttl,
                        "auth": True,
                    }
                )
            else:
                content = "v=spf1 ~all"
        elif check_for_fail is False:
            if spf_output["pass"]:
                content = spf_output["spf_pass_response"]
                responses.append(
                    {
                        "qname": qname,
                        "qtype": "A",
                        "content": "127.0.0.2",
                        "ttl": settings.default_ttl,
                        "auth": True,
                    }
                )
                responses.append(
                    {
                        "qname": qname,
                        "qtype": "AAAA",
                        "content": "fe80::2",
                        "ttl": settings.default_ttl,
                        "auth": True,
                    }
                )
            else:
                content = spf_output["spf_fail_response"]
        else:
            content = "v=spf1 ?all"

        responses.append(
            {
                "qname": qname,
                "qtype": "TXT",
                "content": content,
                "ttl": settings.default_ttl,
                "auth": True,
            }
        )
        responses.append(
            {
                "qname": qname,
                "qtype": "TXT",
                "content": response_banner,
                "ttl": settings.default_ttl,
                "auth": True,
            }
        )

        return {"result": responses}

    return {"result": responses}


@router.get("/getAllDomains")
async def get_all_domains(deps: RouteDependencies = Depends(get_dependencies)):
    """PowerDNS remote backend getAllDomains endpoint."""
    settings = deps.settings

    return {
        "result": [
            {
                "id": 1,
                "zone": settings.zone_dotted,
                "kind": "NATIVE",
                "serial": int(settings.soa_serial),
            }
        ]
    }


@router.get("/getDomainInfo/{zone}")
async def get_domain_info(
    zone: str, deps: RouteDependencies = Depends(get_dependencies)
):
    """PowerDNS remote backend getDomainInfo endpoint."""
    settings = deps.settings

    if zone.rstrip(".").lower() == settings.zone.rstrip(".").lower():
        return {
            "result": {
                "id": 1,
                "zone": settings.zone_dotted,
                "kind": "NATIVE",
                "serial": int(settings.soa_serial),
                "auth": True,
            }
        }

    return {"result": False, "log": f"I don't serve {zone}"}


@router.get("/getAllDomainMetadata/{zone_name}")
async def get_all_domain_metadata(zone_name: str):  # pylint: disable=unused-argument
    """PowerDNS remote backend getAllDomainMetadata endpoint."""
    return {"result": {"PRESIGNED": ["0"]}}


@router.get("/getDomainMetadata/{zone_name}/PRESIGNED")
async def get_domain_metadata(zone_name: str):  # pylint: disable=unused-argument
    """PowerDNS remote backend getDomainMetadata endpoint."""
    return {"result": ["0"]}


@router.post("/startTransaction/-1/{zone_name}/{epoch}")
async def start_transaction(
    zone_name: str, epoch: str
):  # pylint: disable=unused-argument
    """PowerDNS remote backend startTransaction endpoint."""
    return {"result": False}
