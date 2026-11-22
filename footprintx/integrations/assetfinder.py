"""Assetfinder wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class AssetfinderIntegration(ToolIntegration):
    name = "assetfinder"
    display_name = "Assetfinder"
    binary = "assetfinder"
    version_args = ()
    install_hint = "go install github.com/tomnomnom/assetfinder@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
