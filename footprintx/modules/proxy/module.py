"""Web proxy integration (spec §5.10)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    ModuleResult,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class ProxyModule(BaseModule):
    name = "proxy"
    description = "Send discovered URLs through Burp Suite / OWASP ZAP for manual review."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe", "web_fuzzing")
    integrations = ("zap",)
    enabled_by_default = False

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
