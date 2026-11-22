"""Dependency-aware execution planning (spec §6.1–6.2).

Modules are grouped into *layers*: everything in a layer can run concurrently,
and each layer only starts after the previous one finishes. Dependencies on
modules that are not part of the scan (disabled, excluded or not applicable)
are ignored rather than blocking the dependant.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from footprintx.modules.base import BaseModule

ExecutionPlan = list[list["BaseModule"]]


class DependencyCycleError(RuntimeError):
    pass


def build_execution_plan(modules: Sequence[BaseModule]) -> ExecutionPlan:
    by_name = {m.name: m for m in modules}
    pending = {m.name: {d for d in m.depends_on if d in by_name} for m in modules}
    plan: ExecutionPlan = []

    while pending:
        ready = [m.name for m in modules if m.name in pending and not pending[m.name]]
        if not ready:
            raise DependencyCycleError(f"circular module dependencies: {sorted(pending)}")
        plan.append([by_name[name] for name in ready])
        for name in ready:
            del pending[name]
        for deps in pending.values():
            deps.difference_update(ready)

    return plan
