"""Collect findings and module statuses from a finished scan."""

from __future__ import annotations

from footprintx.core.context import ScanContext
from footprintx.core.models import Finding


def aggregate(context: ScanContext) -> list[Finding]:
    """All findings from every module, in completion order."""
    raise NotImplementedError
