"""Web technology detection (spec §5.6)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    ModuleResult,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class TechnologyDetectionModule(BaseModule):
    name = "technology_detection"
    description = "Fingerprint web servers, frameworks, CMSs, CDNs and WAFs."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe",)
    integrations = ("whatweb", "httpx")

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
