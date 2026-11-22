"""Top-level scan workflow (spec §6.1): targets → modules → plan → execute → report."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from pathlib import Path

from footprintx.core.config import Settings
from footprintx.core.context import ScanContext
from footprintx.core.models import Target
from footprintx.core.scheduler import ExecutionPlan, build_execution_plan
from footprintx.modules import MODULE_REGISTRY
from footprintx.modules.base import BaseModule


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        registry: Mapping[str, type[BaseModule]] = MODULE_REGISTRY,
    ) -> None:
        self.settings = settings
        self.registry = registry

    def select_modules(
        self, targets: Collection[Target], exclude: Collection[str] = ()
    ) -> list[BaseModule]:
        """Enabled, non-excluded modules that apply to at least one target."""
        selected: list[BaseModule] = []
        for name, module_cls in self.registry.items():
            config = self.settings.module_config(name, module_cls.enabled_by_default)
            if name in exclude or not config.enabled:
                continue
            module = module_cls(config)
            if any(module.applies_to_target(t) for t in targets):
                selected.append(module)
        return selected

    def plan(self, targets: Collection[Target], exclude: Collection[str] = ()) -> ExecutionPlan:
        return build_execution_plan(self.select_modules(targets, exclude))

    async def run(
        self, targets: list[Target], output_dir: Path, exclude: Collection[str] = ()
    ) -> ScanContext:
        # TODO (Phase 1): create session dir (results/<target>/<session_id>/), write
        # scan_info.json + targets.txt, run ExecutionEngine, then reporting pipeline:
        # aggregate → normalise → dedupe → correlate → JSON/HTML/TXT reports.
        raise NotImplementedError("scan execution not implemented yet")
