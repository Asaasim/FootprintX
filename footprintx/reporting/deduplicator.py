"""Merge duplicate findings while keeping every source (spec §9.2)."""

from __future__ import annotations

from footprintx.core.models import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing ``Finding.key``.

    The first occurrence is kept; ``data["sources"]`` lists every tool that reported
    it. Data from later duplicates fills in missing keys, and list values (e.g. the
    hostnames pointing at one IP) are merged.
    """
    merged: dict[tuple[object, ...], Finding] = {}
    for finding in findings:
        existing = merged.get(finding.key)
        if existing is None:
            kept = Finding(finding.kind, finding.value, finding.source, finding.target,
                           {**finding.data, "sources": [finding.source]}, finding.discovered_at)
            merged[finding.key] = kept
            continue
        sources: list[str] = existing.data["sources"]
        if finding.source not in sources:
            sources.append(finding.source)
        for key, value in finding.data.items():
            current = existing.data.get(key)
            if current is None:
                existing.data[key] = value
            elif isinstance(current, list) and isinstance(value, list):
                current.extend(v for v in value if v not in current)
    return list(merged.values())
