"""HTTPx wrapper.

This is ProjectDiscovery's Go ``httpx`` binary, not the Python httpx library —
which FootprintX depends on and which installs its own ``httpx`` script. Those
scripts are recognised by their output and skipped; set ``tools.paths.httpx`` in
config.yaml to point at the Go binary explicitly.
"""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class HttpxIntegration(ToolIntegration):
    name = "httpx"
    display_name = "HTTPx"
    binary = "httpx"
    version_args = ("-version",)
    # Python httpx[cli] prints a click usage line; without the extra it asks for httpx[cli].
    reject_markers = ("[OPTIONS] URL", "httpx[cli]")
    install_hint = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
