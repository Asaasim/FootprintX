"""Per-scan shared state passed to every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from footprintx.core.config import Settings
from footprintx.core.models import Baseline, Finding, FindingKind, ModuleResult, Target
from footprintx.core.scope_manager import ScopeManager
from footprintx.utils.helpers import utc_now


@dataclass
class ScanContext:
    session_id: str
    output_dir: Path
    settings: Settings
    scope: ScopeManager
    targets: list[Target]
    results: dict[str, ModuleResult] = field(default_factory=dict)
    #: Passive mode: only public sources, no traffic to the targets themselves.
    passive: bool = False
    #: Scan depth: "quick" or "thorough" (see footprintx.core.profiles).
    profile: str = "quick"
    #: Previous completed scan of the same targets, for "new since last scan".
    baseline: Baseline | None = None
    status: str = "pending"
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None

    @property
    def mode(self) -> str:
        """How the scan was run: "passive", "quick" or "thorough"."""
        return "passive" if self.passive else self.profile

    @property
    def raw_dir(self) -> Path:
        """Where integrations preserve unmodified tool output (spec §8.2)."""
        return self.output_dir / "raw"

    @property
    def reports_dir(self) -> Path:
        return self.output_dir / "reports"

    @property
    def duration(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def findings(self, kind: FindingKind | None = None) -> list[Finding]:
        """Findings produced so far by completed modules, optionally filtered by kind."""
        return [
            f
            for result in self.results.values()
            for f in result.findings
            if kind is None or f.kind is kind
        ]

    def save_raw(self, name: str, content: str) -> Path:
        """Preserve raw tool output under ``raw/`` and return the file path."""
        path = self.raw_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
