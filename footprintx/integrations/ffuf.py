"""FFUF wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class FfufIntegration(ToolIntegration):
    name = "ffuf"
    display_name = "FFUF"
    binary = "ffuf"
    version_args = ("-V",)
    install_hint = "go install github.com/ffuf/ffuf/v2@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
