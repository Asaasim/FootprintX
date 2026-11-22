"""reports/report.json writer, plus the report model shared by all formats."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from footprintx import __version__
from footprintx.core.context import ScanContext
from footprintx.core.models import SEVERITIES, Finding, FindingKind, ModuleStatus
from footprintx.reporting.correlator import correlate, count_hosts

#: Order of finding sections in reports (observations are shown separately, first).
SECTION_ORDER = [
    FindingKind.SUBDOMAIN, FindingKind.DNS_RECORD, FindingKind.IP_ADDRESS,
    FindingKind.LIVE_HOST, FindingKind.URL, FindingKind.OPEN_PORT, FindingKind.TECHNOLOGY,
    FindingKind.ENDPOINT, FindingKind.EMAIL, FindingKind.INTEL,
]


def build_report_data(context: ScanContext, findings: list[Finding]) -> dict[str, Any]:
    """Shared report model used by the JSON, text and HTML writers."""
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for kind in SECTION_ORDER:
        items = [f.to_dict() for f in findings if f.kind is kind]
        if items:
            by_kind[kind.value] = items

    rank = {s: i for i, s in enumerate(SEVERITIES)}
    observations = sorted(
        (f.to_dict() for f in findings if f.kind is FindingKind.OBSERVATION),
        key=lambda o: (rank.get(o["data"].get("severity", "info"), len(rank)), o["value"]))
    severity_counts = {s: sum(1 for o in observations if o["data"].get("severity") == s)
                       for s in SEVERITIES}

    statuses = {s: [n for n, r in context.results.items() if r.status is s] for s in ModuleStatus}
    assets = correlate(context.targets, findings)
    return {
        "tool": "FootprintX",
        "version": __version__,
        "session_id": context.session_id,
        "status": context.status,
        "mode": "passive" if context.passive else "full",
        "started_at": context.started_at.isoformat(),
        "finished_at": context.finished_at.isoformat() if context.finished_at else None,
        "duration": context.duration,
        "targets": [{"value": t.value, "type": t.type.value} for t in context.targets],
        "summary": {
            "total_findings": len(findings),
            "by_kind": {kind: len(items) for kind, items in by_kind.items()},
            "observations": severity_counts,
            "hosts": count_hosts(assets),
            "names_discovered": len({f.value for f in findings
                                     if f.kind is FindingKind.SUBDOMAIN}),
            "live_websites": len([f for f in findings
                                  if f.kind is FindingKind.URL and f.data.get("live")]),
            "open_ports": len(by_kind.get(FindingKind.OPEN_PORT.value, [])),
            "modules_succeeded": statuses[ModuleStatus.SUCCESS],
            "modules_failed": statuses[ModuleStatus.FAILED],
            "modules_skipped": statuses[ModuleStatus.SKIPPED],
        },
        "observations": observations,
        "assets": assets,
        "modules": [r.to_dict() for r in context.results.values()],
        "findings": by_kind,
    }


def write_json_report(data: dict[str, Any], path: Path) -> Path:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path
