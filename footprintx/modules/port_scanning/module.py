"""Port and service scanning (spec §5.5)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    HOSTNAME_TYPES,
    IP_TYPES,
    ModuleResult,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class PortScanningModule(BaseModule):
    name = "port_scanning"
    description = "Find open ports and identify services and versions."
    applies_to = HOSTNAME_TYPES | IP_TYPES
    depends_on = ("ip_discovery",)
    integrations = ("naabu", "nmap")

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
