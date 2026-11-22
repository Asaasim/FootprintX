"""Collect findings from a scan and write the per-category result files (spec §8)."""

from __future__ import annotations

import json
from pathlib import Path

from footprintx.core.context import ScanContext
from footprintx.core.models import Finding, FindingKind

#: Finding kind → result file in the session directory. ``.txt`` = one value per line.
RESULT_FILES: dict[FindingKind, str] = {
    FindingKind.SUBDOMAIN: "subdomains.txt",
    FindingKind.DNS_RECORD: "dns_records.json",
    FindingKind.IP_ADDRESS: "resolved_ips.txt",
    FindingKind.LIVE_HOST: "live_hosts.txt",
    FindingKind.OPEN_PORT: "open_ports.json",
    FindingKind.TECHNOLOGY: "technologies.json",
    FindingKind.URL: "urls.txt",
    FindingKind.ENDPOINT: "fuzzing_results.json",
    FindingKind.INTEL: "osint_results.json",
}


def aggregate(context: ScanContext) -> list[Finding]:
    """All findings from every module, in module completion order."""
    return context.findings()


def write_result_files(output_dir: Path, findings: list[Finding]) -> list[Path]:
    written: list[Path] = []
    for kind, filename in RESULT_FILES.items():
        items = [f for f in findings if f.kind is kind]
        if not items:
            continue
        path = output_dir / filename
        if path.suffix == ".txt":
            path.write_text("".join(f"{v}\n" for v in sorted({f.value for f in items})),
                            encoding="utf-8")
        else:
            path.write_text(json.dumps([f.to_dict() for f in items], indent=2),
                            encoding="utf-8")
        written.append(path)
    return written
