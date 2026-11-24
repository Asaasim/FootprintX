"""Recognise CDN edge servers, whose open ports are not the organisation's own.

A site behind Cloudflare resolves to Cloudflare's servers, which answer on the
same set of ports for every customer (80, 443, 8080, 8443, 2052, …). Reporting
those as the organisation's open ports is misleading, so they are labelled.

Ranges: https://www.cloudflare.com/ips/ (stable for years; update when it changes).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

CLOUDFLARE_RANGES = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)


@lru_cache(maxsize=1)
def _networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(r) for r in CLOUDFLARE_RANGES)


def cdn_for_ip(ip: str | None) -> str | None:
    """The CDN operating ``ip`` (currently Cloudflare only), else None."""
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(address in net for net in _networks() if net.version == address.version):
        return "Cloudflare"
    return None
