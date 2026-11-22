"""Subdomain discovery (spec §5.1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    ModuleResult,
    TargetType,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class SubdomainModule(BaseModule):
    name = "subdomains"
    description = "Discover subdomains via passive sources and certificate transparency."
    applies_to = frozenset({TargetType.DOMAIN})
    depends_on = ()
    integrations = ("subfinder", "amass", "assetfinder", "crtsh")

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
