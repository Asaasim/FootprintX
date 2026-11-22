"""Naabu wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class NaabuIntegration(ToolIntegration):
    name = "naabu"
    display_name = "Naabu"
    binary = "naabu"
    version_args = ("-version",)
    install_hint = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
