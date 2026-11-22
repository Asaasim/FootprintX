"""Execution engine: runs an execution plan's layers (spec §6.2–6.3)."""

from __future__ import annotations

from footprintx.core.config import Settings
from footprintx.core.context import ScanContext
from footprintx.core.models import ModuleResult
from footprintx.core.scheduler import ExecutionPlan


class ExecutionEngine:
    """Runs each layer's modules concurrently (bounded by ``execution.concurrency``),
    layers in order, each module under ``execution.module_timeout``.

    A module that raises or times out yields a FAILED :class:`ModuleResult`; it never
    aborts the scan. Results are written to ``context.results`` as they complete so
    partial results survive interruption.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def execute(self, plan: ExecutionPlan, context: ScanContext) -> dict[str, ModuleResult]:
        # TODO (Phase 1): asyncio.Semaphore + wait_for per module, catch exceptions,
        # record timings/status, honour Ctrl+C for graceful termination.
        raise NotImplementedError("execution engine not implemented yet")
