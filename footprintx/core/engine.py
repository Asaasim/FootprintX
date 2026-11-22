"""Execution engine: runs an execution plan's layers (spec §6.2–6.3)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from footprintx.core.config import Settings
from footprintx.core.context import ScanContext
from footprintx.core.logger import get_logger
from footprintx.core.models import ModuleResult, ModuleStatus
from footprintx.core.scheduler import ExecutionPlan
from footprintx.modules.base import BaseModule
from footprintx.utils.helpers import utc_now

log = get_logger("engine")

ResultCallback = Callable[[ModuleResult], None]
StartCallback = Callable[[str], None]


class ExecutionEngine:
    """Runs each layer's modules concurrently (bounded by ``execution.concurrency``),
    layers in order, each module under ``execution.module_timeout``.

    A module that raises or times out yields a FAILED :class:`ModuleResult`; it never
    aborts the scan unless ``execution.continue_on_error`` is false. Results land in
    ``context.results`` as each module finishes, so partial results survive Ctrl+C.
    """

    def __init__(
        self,
        settings: Settings,
        on_result: ResultCallback | None = None,
        on_start: StartCallback | None = None,
    ) -> None:
        self.settings = settings
        self.on_result = on_result
        self.on_start = on_start

    async def execute(self, plan: ExecutionPlan, context: ScanContext) -> dict[str, ModuleResult]:
        semaphore = asyncio.Semaphore(self.settings.execution.concurrency)
        for index, layer in enumerate(plan):
            await asyncio.gather(*(self._run_module(m, context, semaphore) for m in layer))

            failed = [m.name for m in layer
                      if context.results[m.name].status is ModuleStatus.FAILED]
            if failed and not self.settings.execution.continue_on_error:
                reason = f"scan stopped after failure of: {', '.join(failed)}"
                for module in (m for later in plan[index + 1:] for m in later):
                    self._record(context, ModuleResult(
                        module.name, ModuleStatus.SKIPPED, skip_reason=reason))
                break
        return context.results

    async def _run_module(
        self, module: BaseModule, context: ScanContext, semaphore: asyncio.Semaphore
    ) -> None:
        timeout = self.settings.execution.module_timeout
        async with semaphore:
            started = utc_now()
            log.info("Running module %s", module.name)
            if self.on_start is not None:
                self.on_start(module.name)
            try:
                result = await asyncio.wait_for(module.run(context), timeout)
            except NotImplementedError:
                result = ModuleResult(module.name, ModuleStatus.SKIPPED,
                                      skip_reason="not implemented yet")
            except TimeoutError:
                result = ModuleResult(module.name, ModuleStatus.FAILED,
                                      errors=[f"timed out after {timeout:g}s"])
            except asyncio.CancelledError:
                self._record(context, ModuleResult(
                    module.name, ModuleStatus.FAILED, errors=["interrupted"],
                    started_at=started, finished_at=utc_now()))
                raise
            except Exception as exc:  # noqa: BLE001 — module isolation is the point
                log.exception("Module %s failed", module.name)
                result = ModuleResult(module.name, ModuleStatus.FAILED,
                                      errors=[f"{type(exc).__name__}: {exc}"])

        result.started_at = result.started_at or started
        result.finished_at = utc_now()
        self._record(context, result)

    def _record(self, context: ScanContext, result: ModuleResult) -> None:
        context.results[result.module] = result
        if self.on_result is not None:
            self.on_result(result)
