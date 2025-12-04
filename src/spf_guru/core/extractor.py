"""SPF record extraction and flattening logic."""

# pylint: disable=missing-function-docstring

import asyncio
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Optional, Protocol, Tuple

from spf_guru.core.cache import CacheManager, get_cache_manager
from spf_guru.core.config import Settings, get_settings
from spf_guru.dns.resolver import get_mx_ips, get_txt_records, resolve_a, resolve_aaaa
from spf_guru.utils.exceptions import SPFExtractionError, capture_exception


class DNSResolver(Protocol):
    """Protocol for DNS resolution operations."""

    async def get_txt_records(self, domain: str) -> Tuple[list[str], Optional[int]]: ...

    async def resolve_a(self, domain: str) -> Tuple[list[str], Optional[int]]: ...

    async def resolve_aaaa(self, domain: str) -> Tuple[list[str], Optional[int]]: ...

    async def get_mx_ips(
        self, domain: str
    ) -> Tuple[list[str], list[Optional[int]]]: ...


@dataclass
class DefaultDNSResolver:
    """Default DNS resolver using the dns.resolver module."""

    async def get_txt_records(self, domain: str) -> Tuple[list[str], Optional[int]]:
        return await get_txt_records(domain)

    async def resolve_a(self, domain: str) -> Tuple[list[str], Optional[int]]:
        return await resolve_a(domain)

    async def resolve_aaaa(self, domain: str) -> Tuple[list[str], Optional[int]]:
        return await resolve_aaaa(domain)

    async def get_mx_ips(self, domain: str) -> Tuple[list[str], list[Optional[int]]]:
        return await get_mx_ips(domain)


@dataclass
class SPFExtractor:
    """Extracts and flattens SPF records for a domain."""

    settings: Settings = field(default_factory=get_settings)
    resolver: DNSResolver = field(default_factory=DefaultDNSResolver)
    cache: CacheManager = field(default_factory=get_cache_manager)

    # In-flight request protection to prevent duplicate work
    _in_flight: dict[str, asyncio.Future] = field(default_factory=dict)

    async def extract_spf(
        self,
        domain: str,
        seen: Optional[set[str]] = None,
    ) -> Tuple[list[str], list[str], list[int], list[str]]:
        """
        Recursively extract IPs from SPF records.

        Returns: (ips, macro_mechanisms, all_ttls_seen, invalid_ips)
        """
        if seen is None:
            seen = set()

        zone = self.settings.zone.rstrip(".").lower()

        if domain in seen:
            return [], [], [], []

        seen.add(domain)

        txts, txt_ttl = await self.resolver.get_txt_records(domain)
        spfs = [t for t in txts if t.lower().startswith("v=spf1")]

        if not spfs:
            return [], [], [], []

        ips: list[str] = []
        macros: list[str] = []
        includes: list[str] = []
        all_ttls: list[int] = []
        invalid_ips: list[str] = []

        if txt_ttl:
            all_ttls.append(txt_ttl)

        mx_tasks: list[asyncio.Task] = []
        a_tasks: list[asyncio.Task] = []

        for spf in spfs:
            for mech in spf.split()[1:]:
                mech_clean = mech.lstrip("+-~?")  # handle qualifiers
                mech_l = mech_clean.lower()

                # --- MACROS: don't add to recurse
                if "%{" in mech_clean:
                    if zone in mech_l:
                        # These are spf guru macro tokens - ignore
                        continue

                    fixup_macros = mech.replace("%{d}", "%{o}")
                    macros.append(fixup_macros)  # keep original casing
                    continue

                # --- ip4/ip6 with validation
                if mech_l.startswith(("ip4:", "ip6:")):
                    _, net = mech_clean.split(":", 1)
                    try:
                        if mech_l.startswith("ip4:"):
                            ipaddress.IPv4Network(net, strict=False)
                        else:
                            ipaddress.IPv6Network(net, strict=False)
                        ips.append(net)
                    except ValueError:
                        invalid_ips.append(net)
                    continue

                # --- A / MX (optionally with domain)
                if mech_l == "a" or mech_l.startswith("a:"):
                    a_dom = domain if mech_clean == "a" else mech_clean.split(":", 1)[1]
                    a_tasks.append(asyncio.create_task(self.resolver.resolve_a(a_dom)))
                    a_tasks.append(
                        asyncio.create_task(self.resolver.resolve_aaaa(a_dom))
                    )
                    continue

                if mech_l == "mx" or mech_l.startswith("mx:"):
                    mx_dom = (
                        domain if mech_clean == "mx" else mech_clean.split(":", 1)[1]
                    )
                    mx_tasks.append(
                        asyncio.create_task(self.resolver.get_mx_ips(mx_dom))
                    )
                    continue

                # --- include / redirect (only static)
                if mech_l.startswith("include:") and "%{" not in mech_clean:
                    includes.append(mech_clean.split(":", 1)[1])
                    continue

                if mech_l.startswith("redirect=") and "%{" not in mech_clean:
                    includes.append(mech_clean.split("=", 1)[1])
                    continue

                # --- exists:/ptr and leftovers (non-flattenable but no macros)
                if mech_l.startswith("exists:") or mech_l.startswith("ptr"):
                    invalid_ips.append(mech)
                    continue

                # all/~all/?all: nothing to collect
                if mech_l.endswith("all"):
                    continue

                # invalid
                invalid_ips.append(mech)

        # process MX tasks
        if mx_tasks:
            mx_results = await asyncio.gather(*mx_tasks, return_exceptions=True)
            for res in mx_results:
                if isinstance(res, Exception):
                    continue
                sub_ips, sub_ttls = res
                ips.extend(sub_ips)
                all_ttls.extend(t for t in sub_ttls if t)

        # process A/AAAA tasks
        if a_tasks:
            a_results = await asyncio.gather(*a_tasks, return_exceptions=True)
            for res in a_results:
                if isinstance(res, Exception):
                    continue

                sub_ips, sub_ttl = res
                ips.extend(sub_ips)

                if sub_ttl:
                    all_ttls.append(sub_ttl)

        # recurse includes
        for inc in includes:
            sub_ips, sub_macros, sub_ttls, sub_invalids = await self.extract_spf(
                inc, seen
            )
            ips.extend(sub_ips)
            macros.extend(sub_macros)
            all_ttls.extend(t for t in sub_ttls if t)
            invalid_ips.extend(sub_invalids)

        return list(set(ips)), macros, all_ttls, invalid_ips

    async def get_or_compute_spf(self, domain: str) -> dict:
        """
        Get SPF data for a domain, using cache and in-flight protection.

        Returns dict with: domain, ips, macro_records, invalid_addr
        """
        cache_key = f"spf:{domain}"

        # 1) Try cache normally
        if cached := await self.cache.get(cache_key):
            return json.loads(cached)

        # 2) In-flight protection
        if domain in self._in_flight:
            return await self._in_flight[domain]  # wait for first request's result

        # 3) We are the first => create a shared future and store it
        fut = asyncio.get_running_loop().create_future()
        self._in_flight[domain] = fut

        try:
            # Perform extraction
            ips, macros, ttls, invalid_addr = await self.extract_spf(domain)
            positive_ttls = [t for t in ttls if t > 0]
            base_ttl = min(positive_ttls) if positive_ttls else 0
            effective_ttl = max(base_ttl, self.settings.default_ttl)
            result = {
                "domain": domain,
                "ips": ips,
                "macro_records": macros,
                "invalid_addr": invalid_addr,
            }

            # Write to cache
            await self.cache.set(cache_key, json.dumps(result), effective_ttl, log=True)

            # Resolve the future for any waiters
            fut.set_result(result)
            return result

        except Exception as e:
            # Report unexpected errors during SPF extraction
            capture_exception(
                SPFExtractionError(f"SPF extraction failed for {domain}: {e}"),
                {"domain": domain},
            )
            fut.set_exception(e)
            raise

        finally:
            # cleanup: ensure future is removed after completion
            self._in_flight.pop(domain, None)


# Default extractor instance
_extractor: Optional[SPFExtractor] = None


def get_extractor() -> SPFExtractor:
    """Get or create the default SPF extractor."""
    global _extractor

    if _extractor is None:
        _extractor = SPFExtractor()

    return _extractor


def set_extractor(extractor: SPFExtractor) -> None:
    """Set a custom extractor (useful for testing)."""
    global _extractor

    _extractor = extractor


def reset_extractor() -> None:
    """Reset the extractor (useful for testing)."""
    global _extractor

    _extractor = None


async def get_or_compute_spf(domain: str) -> dict:
    """Get SPF data for a domain, using cache and in-flight protection."""
    return await get_extractor().get_or_compute_spf(domain)
