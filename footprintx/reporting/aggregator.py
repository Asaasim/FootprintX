"""Collect findings from a scan and write the per-category result files (spec §8)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from footprintx.core.context import ScanContext
from footprintx.core.models import Finding, FindingKind
from footprintx.utils.sanitize import redact

Selector = Callable[[Finding], bool]


def _kind(*kinds: FindingKind) -> Selector:
    return lambda f: f.kind in kinds


#: Result file in the session directory → which findings go in it.
#: ``.txt`` files hold one unique value per line; ``.json`` files the full findings.
RESULT_FILES: list[tuple[str, Selector]] = [
    ("subdomains.txt", _kind(FindingKind.SUBDOMAIN)),
    ("dns_records.json", _kind(FindingKind.DNS_RECORD)),
    ("resolved_ips.txt", _kind(FindingKind.IP_ADDRESS)),
    ("live_hosts.txt", _kind(FindingKind.LIVE_HOST)),
    ("open_ports.json", _kind(FindingKind.OPEN_PORT)),
    ("technologies.json", _kind(FindingKind.TECHNOLOGY)),
    ("urls.txt", _kind(FindingKind.URL, FindingKind.ENDPOINT)),
    ("fuzzing_results.json", _kind(FindingKind.ENDPOINT)),
    ("shodan_results.json", lambda f: f.source == "shodan"),
    ("osint_results.json", lambda f: (f.kind is FindingKind.EMAIL)
     or (f.kind is FindingKind.INTEL and f.source != "shodan")),
    ("observations.json", _kind(FindingKind.OBSERVATION)),
]


def aggregate(context: ScanContext) -> list[Finding]:
    """All findings from every module, in module completion order."""
    return context.findings()


def write_result_files(output_dir: Path, findings: list[Finding]) -> list[Path]:
    written: list[Path] = []
    for filename, selector in RESULT_FILES:
        items = [f for f in findings if selector(f)]
        if not items:
            continue
        path = output_dir / filename
        if path.suffix == ".txt":
            text = "".join(f"{v}\n" for v in sorted({f.value for f in items}))
        else:
            text = json.dumps([f.to_dict() for f in items], indent=2, default=str)
        path.write_text(redact(text), encoding="utf-8")
        written.append(path)
    return written
