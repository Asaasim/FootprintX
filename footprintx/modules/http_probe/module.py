"""Live host and URL detection (spec §5.4)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    ModuleResult,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class HttpProbeModule(BaseModule):
    name = "http_probe"
    description = "Detect live hosts/URLs: status, title, server, redirects, TLS."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("ip_discovery",)
    integrations = ("httpx",)

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
