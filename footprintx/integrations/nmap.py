"""Nmap wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class NmapIntegration(ToolIntegration):
    name = "nmap"
    display_name = "Nmap"
    binary = "nmap"
    version_args = ("--version",)
    install_hint = "apt install nmap  (or https://nmap.org/download)"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
