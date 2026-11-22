"""Merge duplicate findings while keeping every source (spec §9.2)."""

from __future__ import annotations

from footprintx.core.models import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing ``Finding.key``; record all sources in ``data["sources"]``."""
    raise NotImplementedError
