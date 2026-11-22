"""Amass wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class AmassIntegration(ToolIntegration):
    name = "amass"
    display_name = "Amass"
    binary = "amass"
    version_args = ("-version",)
    install_hint = "go install -v github.com/owasp-amass/amass/v5/cmd/amass@main"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
