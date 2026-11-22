"""Input validators."""

from __future__ import annotations

import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


_HOST_TOKEN = re.compile(r"[A-Za-z0-9*][A-Za-z0-9.*_-]*\.[A-Za-z]{2,63}\.?")


def hostnames_in(text: str, domain: str | None = None) -> list[str]:
    """Unique valid hostnames found anywhere in ``text`` (order preserved).

    Wildcard prefixes (``*.``) are stripped. With ``domain``, only that domain and
    its subdomains are returned.
    """
    seen: set[str] = set()
    hosts: list[str] = []
    for token in _HOST_TOKEN.findall(text):
        host = token.lower().rstrip(".").removeprefix("*.")
        if host in seen or not is_valid_hostname(host):
            continue
        if domain and not (host == domain or host.endswith("." + domain)):
            continue
        seen.add(host)
        hosts.append(host)
    return hosts


def is_valid_hostname(host: str) -> bool:
    """RFC 1123 hostname with at least two labels and a non-numeric TLD (ASCII/punycode)."""
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    return all(_LABEL.match(label) for label in labels)
