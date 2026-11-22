"""Subfinder wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class SubfinderIntegration(ToolIntegration):
    name = "subfinder"
    display_name = "Subfinder"
    binary = "subfinder"
    version_args = ("-version",)
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
