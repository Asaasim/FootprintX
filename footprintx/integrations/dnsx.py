"""DNSx wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class DnsxIntegration(ToolIntegration):
    name = "dnsx"
    display_name = "DNSx"
    binary = "dnsx"
    version_args = ("-version",)
    install_hint = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
