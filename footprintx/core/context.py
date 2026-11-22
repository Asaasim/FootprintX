"""Per-scan shared state passed to every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from footprintx.core.config import Settings
from footprintx.core.models import Finding, FindingKind, ModuleResult, Target
from footprintx.core.scope_manager import ScopeManager


@dataclass
class ScanContext:
    session_id: str
    output_dir: Path
    settings: Settings
    scope: ScopeManager
    targets: list[Target]
    results: dict[str, ModuleResult] = field(default_factory=dict)

    @property
    def raw_dir(self) -> Path:
        """Where integrations preserve unmodified tool output (spec §8.2)."""
        return self.output_dir / "raw"

    @property
    def reports_dir(self) -> Path:
        return self.output_dir / "reports"

    def findings(self, kind: FindingKind | None = None) -> list[Finding]:
        """Findings produced so far by completed modules, optionally filtered by kind."""
        return [
            f
            for result in self.results.values()
            for f in result.findings
            if kind is None or f.kind is kind
        ]
