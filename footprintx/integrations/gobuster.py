"""Gobuster wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class GobusterIntegration(ToolIntegration):
    name = "gobuster"
    display_name = "Gobuster"
    binary = "gobuster"
    version_args = ("version",)
    install_hint = "go install github.com/OJ/gobuster/v3@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
