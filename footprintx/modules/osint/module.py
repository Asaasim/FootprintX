"""OSINT and external intelligence (spec §5.8)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    HOSTNAME_TYPES,
    ModuleResult,
    TargetType,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class OsintModule(BaseModule):
    name = "osint"
    description = "Gather public intelligence: domains, IPs, emails, infrastructure."
    applies_to = HOSTNAME_TYPES | {TargetType.IPV4, TargetType.IPV6}
    depends_on = ()
    integrations = ("amass", "crtsh")

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
