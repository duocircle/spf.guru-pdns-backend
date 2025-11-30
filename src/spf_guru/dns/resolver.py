"""DNS resolution utilities."""

import asyncio
from typing import Tuple

import dns.asyncresolver
import dns.exception
import dns.resolver

from spf_guru.utils.exceptions import capture_exception, is_expected_dns_error

# Module-level resolver instance
resolver = dns.asyncresolver.Resolver()

# Expected DNS errors that shouldn't be reported to Sentry
EXPECTED_DNS_ERRORS = (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.exception.Timeout,
)


async def get_txt_records(domain: str) -> Tuple[list[str], int]:
    """
    Get TXT records for a domain.

    Returns (list of full TXT strings, ttl).
    Joins any <255-char> segments into their logical whole.
    """
    try:
        answer = await resolver.resolve(domain, "TXT")
        full_texts: list[str] = []

        for rdata in answer:
            joined = b"".join(rdata.strings).decode("utf-8")
            full_texts.append(joined)

        return full_texts, answer.rrset.ttl

    except EXPECTED_DNS_ERRORS:
        return [], 0
    except Exception as e:
        capture_exception(e, {"domain": domain, "record_type": "TXT"})
        return [], 0


async def resolve_a(hostname: str) -> Tuple[list[str], int]:
    """Resolve A records for a hostname."""
    try:
        ans = await resolver.resolve(hostname, "A")
        return [r.address for r in ans], ans.rrset.ttl
    except EXPECTED_DNS_ERRORS:
        return [], 0
    except Exception as e:
        capture_exception(e, {"hostname": hostname, "record_type": "A"})
        return [], 0


async def resolve_aaaa(hostname: str) -> Tuple[list[str], int]:
    """Resolve AAAA records for a hostname."""
    try:
        ans = await resolver.resolve(hostname, "AAAA")
        return [r.address for r in ans], ans.rrset.ttl
    except EXPECTED_DNS_ERRORS:
        return [], 0
    except Exception as e:
        capture_exception(e, {"hostname": hostname, "record_type": "AAAA"})
        return [], 0


async def get_mx_ips(mx_domain: str) -> Tuple[list[str], list[int]]:
    """
    Get all IP addresses for a domain's MX records.

    Returns (list of IPs, list of TTLs).
    """
    ips: list[str] = []
    ttls: list[int] = []

    try:
        mx_ans = await resolver.resolve(mx_domain, "MX")
        ttls.append(mx_ans.rrset.ttl)
    except EXPECTED_DNS_ERRORS:
        return ips, ttls
    except Exception as e:
        capture_exception(e, {"domain": mx_domain, "record_type": "MX"})
        return ips, ttls

    tasks = []
    for r in mx_ans:
        exch = r.exchange.to_text().rstrip(".")
        tasks.append(asyncio.create_task(resolve_a(exch)))
        tasks.append(asyncio.create_task(resolve_aaaa(exch)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, Exception):
            # Unexpected errors from gather - report them
            if not is_expected_dns_error(res):
                capture_exception(res, {"domain": mx_domain, "operation": "mx_ip_lookup"})
            continue
        sub_ips, sub_ttl = res
        ips.extend(sub_ips)
        if sub_ttl:
            ttls.append(sub_ttl)

    return ips, ttls
