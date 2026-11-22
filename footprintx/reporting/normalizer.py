"""Bring findings from different tools to consistent field values (spec §9.1)."""

from __future__ import annotations

import contextlib
import ipaddress

from footprintx.core.models import Finding, FindingKind

_HOSTNAME_KINDS = {FindingKind.SUBDOMAIN, FindingKind.LIVE_HOST}


def normalize(findings: list[Finding]) -> list[Finding]:
    """Lower-case hostnames, strip wildcard prefixes/trailing dots, compress IPs (in place)."""
    for finding in findings:
        value = finding.value.strip()
        if finding.kind in _HOSTNAME_KINDS:
            value = value.lower().rstrip(".").removeprefix("*.")
        elif finding.kind is FindingKind.IP_ADDRESS:
            with contextlib.suppress(ValueError):
                value = ipaddress.ip_address(value).compressed
        finding.value = value
    return findings
