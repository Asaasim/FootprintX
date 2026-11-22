"""reports/findings.csv — every finding as one spreadsheet row (spec §8.2, optional).

Values come from scanned systems, so cells that a spreadsheet would treat as a
formula (``=``, ``+``, ``-``, ``@``, tab, CR) are prefixed with an apostrophe —
otherwise a hostile page title like ``=HYPERLINK(...)`` would run when the CSV
is opened in Excel or LibreOffice (CSV/formula injection).
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from footprintx.utils.sanitize import redact

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
COLUMNS = ["kind", "value", "target", "severity", "sources", "discovered_at", "details"]


def neutralise(cell: str) -> str:
    return "'" + cell if cell.startswith(_FORMULA_PREFIXES) else cell


def render_csv(data: dict[str, Any]) -> str:
    rows: list[dict[str, Any]] = [*data["observations"]]
    for items in data["findings"].values():
        rows.extend(items)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for f in rows:
        details = {k: v for k, v in f["data"].items() if k not in ("sources", "severity")}
        writer.writerow([neutralise(str(cell)) for cell in (
            f["kind"], f["value"], f.get("target") or "", f["data"].get("severity", ""),
            ", ".join(f["data"].get("sources", [f["source"]])), f["discovered_at"],
            json.dumps(details, default=str) if details else "",
        )])
    return buffer.getvalue()


def write_csv_report(data: dict[str, Any], path: Path) -> Path:
    path.write_text(redact(render_csv(data)), encoding="utf-8")
    return path
