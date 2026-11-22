"""reports/report.txt writer."""

from __future__ import annotations

from pathlib import Path

from footprintx.core.context import ScanContext
from footprintx.reporting.correlator import AssetNode


def write_text_report(context: ScanContext, assets: list[AssetNode], path: Path) -> Path:
    raise NotImplementedError
