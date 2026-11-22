"""Top-level scan workflow (spec §6.1): targets → modules → plan → execute → report."""

from __future__ import annotations

import json
import os
from collections.abc import Collection, Mapping
from pathlib import Path

from footprintx import __version__
from footprintx.core.config import Settings
from footprintx.core.context import ScanContext
from footprintx.core.engine import ExecutionEngine, ResultCallback, StartCallback
from footprintx.core.logger import attach_log_file, detach_log_file, get_logger
from footprintx.core.models import ModuleResult, ModuleStatus, Target
from footprintx.core.scheduler import ExecutionPlan, build_execution_plan
from footprintx.core.scope_manager import ScopeManager
from footprintx.database.history import previous_scan
from footprintx.database.storage import HISTORY_DB, Storage
from footprintx.modules import MODULE_REGISTRY
from footprintx.modules.base import BaseModule
from footprintx.reporting.pipeline import generate_reports
from footprintx.utils.helpers import restore_ownership, safe_dirname, unique_session_dir, utc_now
from footprintx.utils.sanitize import redact

log = get_logger("orchestrator")


class Orchestrator:
    def __init__(
        self,
        settings: Settings,
        registry: Mapping[str, type[BaseModule]] = MODULE_REGISTRY,
    ) -> None:
        self.settings = settings
        self.registry = registry

    def select_modules(
        self, targets: Collection[Target], exclude: Collection[str] = (), passive: bool = False
    ) -> tuple[list[BaseModule], dict[str, str]]:
        """Modules to run, plus ``{name: reason}`` for every module left out."""
        selected: list[BaseModule] = []
        skipped: dict[str, str] = {}
        for name, module_cls in self.registry.items():
            config = self.settings.module_config(name, module_cls.enabled_by_default)
            if name in exclude:
                skipped[name] = "excluded on command line"
            elif not config.enabled:
                skipped[name] = "disabled in configuration"
            elif passive and module_cls.active:
                skipped[name] = "passive mode (contacts the target directly)"
            else:
                module = module_cls(config)
                if any(module.applies_to_target(t) for t in targets):
                    selected.append(module)
                else:
                    skipped[name] = "not applicable to the supplied targets"
        return selected, skipped

    def plan(self, targets: Collection[Target], exclude: Collection[str] = (),
             passive: bool = False) -> ExecutionPlan:
        return build_execution_plan(self.select_modules(targets, exclude, passive)[0])

    async def run(
        self,
        targets: list[Target],
        scope: ScopeManager,
        output_root: Path,
        exclude: Collection[str] = (),
        on_result: ResultCallback | None = None,
        on_start: StartCallback | None = None,
        passive: bool = False,
    ) -> ScanContext:
        """Run a full scan. Reports and scan_info.json are written even if interrupted."""
        output_root = output_root.expanduser()
        label = safe_dirname(targets[0].value) if len(targets) == 1 else "multi_target"
        output_dir = unique_session_dir(output_root / label)
        context = ScanContext(output_dir.name, output_dir, self.settings, scope, targets,
                              passive=passive)

        try:
            context.baseline = previous_scan(Storage(output_root / HISTORY_DB),
                                             [t.value for t in targets], passive)
        except Exception:  # noqa: BLE001 — change detection is a convenience, never fatal
            log.exception("Could not read scan history")

        modules, skipped = self.select_modules(targets, exclude, passive)
        plan = build_execution_plan(modules)
        for name, reason in skipped.items():
            context.results[name] = ModuleResult(name, ModuleStatus.SKIPPED, skip_reason=reason)

        output_dir.mkdir(parents=True)
        if os.name == "posix":
            os.chmod(output_dir, 0o700)  # scan results are sensitive: owner-only access
        context.raw_dir.mkdir(exist_ok=True)
        log_handler = attach_log_file(output_dir / "scan.log", self.settings.logging.level)
        log.info("Scan %s started: %s", context.session_id, ", ".join(t.value for t in targets))
        log.info("Plan: %s", " -> ".join(",".join(m.name for m in layer) for layer in plan))
        (output_dir / "targets.txt").write_text(
            "".join(f"{t.value}\n" for t in targets), encoding="utf-8")
        context.status = "running"
        self._write_scan_info(context, plan)

        engine = ExecutionEngine(self.settings, on_result, on_start)
        try:
            await engine.execute(plan, context)
            context.status = "completed"
        except BaseException:
            context.status = "interrupted"
            raise
        finally:
            context.finished_at = utc_now()
            try:
                generate_reports(context)
            except Exception:  # noqa: BLE001 — never lose scan_info because a report broke
                log.exception("Report generation failed")
            self._write_scan_info(context, plan)
            try:
                Storage(output_root / HISTORY_DB).save_scan(context)
            except Exception:  # noqa: BLE001 — history is a convenience, never fatal
                log.exception("Saving scan history failed")
            log.info("Scan %s %s in %.1fs", context.session_id, context.status,
                     context.duration or 0)
            detach_log_file(log_handler)
            restore_ownership(output_dir, parents=(output_dir.parent, output_root,
                                                   output_root / HISTORY_DB))
        return context

    @staticmethod
    def _write_scan_info(context: ScanContext, plan: ExecutionPlan) -> None:
        info = {
            "tool": "FootprintX",
            "version": __version__,
            "session_id": context.session_id,
            "status": context.status,
            "mode": "passive" if context.passive else "full",
            "started_at": context.started_at.isoformat(),
            "finished_at": context.finished_at.isoformat() if context.finished_at else None,
            "duration": context.duration,
            "targets": [{"value": t.value, "type": t.type.value} for t in context.targets],
            "plan": [[m.name for m in layer] for layer in plan],
            "modules": {name: r.to_dict() for name, r in context.results.items()},
        }
        (context.output_dir / "scan_info.json").write_text(
            redact(json.dumps(info, indent=2)), encoding="utf-8")
