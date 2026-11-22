"""IP discovery and enumeration (spec §5.3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    ModuleResult,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class IpDiscoveryModule(BaseModule):
    name = "ip_discovery"
    description = "Resolve hosts to IPs, map IPs to hostnames, expand authorised ranges."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("dns",)
    integrations = ("dnsx", "naabu", "nmap")

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
