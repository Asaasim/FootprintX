"""Shodan integration (spec §5.9)."""

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


class ShodanModule(BaseModule):
    name = "shodan"
    description = "Query Shodan for indexed ports, banners and vulnerability indicators."
    applies_to = HOSTNAME_TYPES | IP_TYPES
    depends_on = ("ip_discovery",)
    integrations = ("shodan",)

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
