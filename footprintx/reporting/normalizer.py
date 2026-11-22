"""Bring findings from different tools to consistent field values (spec §9.1).

e.g. lower-case hostnames, strip trailing dots, canonical URL form, compressed IPv6.
"""

from __future__ import annotations

from footprintx.core.models import Finding


def normalize(findings: list[Finding]) -> list[Finding]:
    raise NotImplementedError
