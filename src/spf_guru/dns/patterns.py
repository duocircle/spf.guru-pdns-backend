"""DNS query pattern matching for SPF Guru."""

import ipaddress
import re
from typing import List, Optional

from spf_guru.core.config import Settings, get_settings

# Sentinel value for unauthorized SPF
UNAUTH_SENTINEL = "v=spf1 ?all"

# Precompiled regex patterns for IP validation
_RE_IPV4 = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)

_RE_IPV6_NIBBLE = re.compile(r"^(?:[0-9A-Fa-f]\.){31}[0-9A-Fa-f]$")


def _compile_patterns(settings: Settings) -> dict:
    """Compile regex patterns based on settings."""
    zone = re.escape(settings.zone_dotted)

    # VENDOR_PATTERN = {d}._i.%{ir}.my.spf.guru.
    vendor_pattern = (
        r"^(([a-zA-Z0-9\-_]{1,63}\.){1,5}[a-zA-Z0-9\-_]{2,24}\.)"
        r"_([izf])\."
        r"(([\d]{1,3}.){3}\d{1,3}|([\da-fA-F]{1}\.){31}[\da-fA-F]{1})\."
        rf"({zone})$"
    )

    # MIMECAST_PATTERN = {8char}._i.%{ir}.my.spf.guru.
    mimecast_pattern = (
        r"^([a-z\d]{8}\.)"
        r"_([izf])\."
        r"(([\d]{1,3}.){3}\d{1,3}|([\da-fA-F]{1}\.){31}[\da-fA-F]{1})\."
        rf"({zone})$"
    )

    # D_PATTERN = i.{ir}._d.%{d}.my.spf.guru.
    d_pattern = (
        r"^[ifz]\."
        r"(([\d]{1,3}\.){3}\d{1,3}|([\da-fA-F]{1}\.){31}[\da-fA-F]{1})\."
        r"_d\."
        r"(([a-zA-Z0-9.\-_]{1,255})\.([a-zA-Z0-9.\-_]{2,255}))\."
        rf"({zone})$"
    )

    # RBLDNSD_PATTERN = %{ir}.%{d}.my.spf.guru.
    rbldnsd_pattern = (
        r"^(((\d{1,3}\.){3}\d{1,3})|(([\da-fA-F]{1}\.){31}[\da-fA-F]{1}))\."
        r"(([a-zA-Z0-9\-_]{2,63}\.){1,5}[a-zA-Z0-9\-_]{2,24})\."
        rf"({zone})$"
    )

    return {
        "vendor": re.compile(vendor_pattern, re.IGNORECASE | re.VERBOSE),
        "mimecast": re.compile(mimecast_pattern, re.IGNORECASE | re.VERBOSE),
        "d": re.compile(d_pattern, re.IGNORECASE | re.VERBOSE),
        "rbldnsd": re.compile(rbldnsd_pattern, re.IGNORECASE | re.VERBOSE),
    }


# Cached patterns (keyed by zone to handle different settings)
_patterns_cache: dict[str, dict] = {}


def _get_patterns(settings: Settings) -> dict:
    """Get compiled patterns for the given settings."""
    zone = settings.zone_dotted
    if zone not in _patterns_cache:
        _patterns_cache[zone] = _compile_patterns(settings)
    return _patterns_cache[zone]


def reset_patterns_cache() -> None:
    """Reset the patterns cache (useful for testing)."""
    _patterns_cache.clear()


def dot2std(ptr: str) -> str:
    """Convert nibble-dot IPv6 format to standard notation."""
    s = ptr.removesuffix(".").removesuffix("ip6.arpa").removesuffix(".")
    parts = s.split(".")

    if len(parts) != 32 or any(len(p) != 1 for p in parts):
        raise ValueError(
            "Expect 32 dot-separated hex nibbles (optionally ending with .ip6.arpa.)"
        )

    for p in parts:
        if p not in "0123456789abcdefABCDEF":
            raise ValueError(f"Invalid hex nibble: {p!r}")

    hexstr = "".join(reversed(parts))

    return str(ipaddress.IPv6Address(int(hexstr, 16)))


def sanitize_spf_record(spf_record: str, settings: Optional[Settings] = None) -> str:
    """Remove SPF Guru specific tokens from an SPF record."""
    if settings is None:
        settings = get_settings()

    tokens: List[str] = spf_record.split()
    prefixes = ("include", "exists")

    to_strip = {f"{p}:{settings.special_spf_record}" for p in prefixes}
    fto_strip = {f"~{p}:{settings.fail_spf_record}" for p in prefixes}

    if any(tok in fto_strip for tok in tokens):
        tokens = [tok for tok in tokens if tok not in fto_strip]

    if any(tok in to_strip for tok in tokens):
        filtered = [tok for tok in tokens if tok not in to_strip]

        return " ".join(filtered)

    return UNAUTH_SENTINEL


def dot_count(s: str) -> int:
    """Determine IP version from dot-notation string."""
    if _RE_IPV4.match(s):
        return 4
    if _RE_IPV6_NIBBLE.match(s):
        return 6

    return 0


def is_ipv6(input_string: str) -> str | bool:
    """
    Validate and convert nibble-dot IPv6 to standard format.

    Returns the standard IPv6 string or False if invalid.
    """
    match = _RE_IPV6_NIBBLE.fullmatch(input_string)

    if match:
        try:
            result = str(ipaddress.ip_address(dot2std(input_string)))
        except Exception:  # pylint: disable=broad-exception-caught
            return False
        return result

    return False


def reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address (for PTR-style lookups)."""
    result = ip.split(".")
    result.reverse()

    return ".".join(result)


def is_ipv4(input_string: str) -> str | bool:
    """
    Validate IPv4 and return reversed format.

    Returns the reversed IPv4 string or False if invalid.
    """
    match = _RE_IPV4.fullmatch(input_string)

    if match:
        try:
            result = str(ipaddress.ip_address(input_string))
        except Exception:  # pylint: disable=broad-exception-caught
            return False
        return reverse_ip(result)

    return False


async def extract_info(
    input_string: str, settings: Optional[Settings] = None
) -> dict | bool:
    """
    Extract domain and IP information from a DNS query name.

    Returns a dict with: ip_address, domain, zone, ip_version, fail_check
    Or False if the query doesn't match any known pattern.
    """
    if not input_string:
        return False

    if settings is None:
        settings = get_settings()

    patterns = _get_patterns(settings)
    mode = settings.spf_record_mode

    match = vendormatch = rbldnsdmatch = mimecastmatch = None

    firsttwo = input_string[:2]
    firsteight = input_string[:8]
    has_dotunderscore_at_nine_ten = "._" in input_string[8:10]

    has_d = "._d." in input_string
    has_i = "._i." in input_string
    has_f = "._f." in input_string
    has_z = "._z." in input_string

    if firsttwo in {"i.", "z.", "f."} and has_d and mode == 0:
        match = patterns["d"].fullmatch(input_string)
    elif (
        "." not in firsteight
        and has_dotunderscore_at_nine_ten
        and (has_i or has_z or has_f)
        and mode == 0
    ):
        mimecastmatch = patterns["mimecast"].fullmatch(input_string)
    elif (has_i or has_z or has_f) and mode == 0:
        vendormatch = patterns["vendor"].fullmatch(input_string)
    elif mode == 1:
        rbldnsdmatch = patterns["rbldnsd"].fullmatch(input_string)
    else:
        return False

    check_for_fail = False

    if match:
        if input_string[0].lower() in ("f", "z"):
            check_for_fail = True

        ip_address = match.group(1)
        domain = match.group(4)
        zone = match.group(7)
    elif vendormatch:
        if vendormatch.group(3).lower() in ("f", "z"):
            check_for_fail = True

        ip_address = vendormatch.group(4)
        domain = vendormatch.group(1)
        zone = vendormatch.group(7)
    elif mimecastmatch:
        if mimecastmatch.group(2).lower() in ("f", "z"):
            check_for_fail = True

        ip_address = mimecastmatch.group(3)
        domain = mimecastmatch.group(1) + "_spf._d.mim.ec."
        zone = mimecastmatch.group(6)
    elif rbldnsdmatch:
        ip_address = rbldnsdmatch.group(2) or rbldnsdmatch.group(4)
        domain = rbldnsdmatch.group(6)
        zone = rbldnsdmatch.group(8)
    else:
        return False

    # Domain control list check
    my_domains = settings.my_domains_set

    if my_domains and domain not in my_domains:
        return False

    ver = dot_count(ip_address)

    if ver == 4:
        ip = is_ipv4(ip_address)
    elif ver == 6:
        ip = is_ipv6(ip_address)
    else:
        return False

    if not ip:
        return False

    return {
        "ip_address": ip,
        "domain": domain,
        "zone": zone,
        "ip_version": ver,
        "fail_check": check_for_fail,
    }


def return_soa(
    qname: str, auth: bool = True, settings: Optional[Settings] = None
) -> list[dict]:
    """Generate SOA record response."""
    if settings is None:
        settings = get_settings()

    def ensure_dot(s: str) -> str:
        s = s.strip()

        if not s.endswith("."):
            s += "."

        return s

    return [
        {
            "qname": qname,
            "qtype": "SOA",
            "content": (
                f"{ensure_dot(settings.primary_ns)} "
                f"{ensure_dot(settings.soa_hostmaster_dotted)} "
                f"{settings.soa_serial} 1800 900 1209600 120"
            ),
            "ttl": 3600,
            "auth": auth,
        }
    ]


def return_ns(qname: str, settings: Optional[Settings] = None) -> list[dict]:
    """Generate NS record responses."""
    if settings is None:
        settings = get_settings()

    def ensure_dot(s: str) -> str:
        s = s.strip()

        if not s.endswith("."):
            s += "."

        return s

    output = []

    for ns in settings.ns_records_list:
        output.append(
            {
                "qname": ensure_dot(qname.lower()),
                "qtype": "NS",
                "content": ensure_dot(ns),
                "ttl": 3600,
                "auth": True,
            }
        )

    return output
