"""Input validators."""

from __future__ import annotations

import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def is_valid_hostname(host: str) -> bool:
    """RFC 1123 hostname with at least two labels and a non-numeric TLD (ASCII/punycode)."""
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    return all(_LABEL.match(label) for label in labels)
