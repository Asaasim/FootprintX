"""Web fuzzing and content discovery (spec §5.7)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    ModuleResult,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class WebFuzzingModule(BaseModule):
    name = "web_fuzzing"
    description = "Discover directories, files and endpoints on live web targets."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe",)
    integrations = ("ffuf", "gobuster")

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
