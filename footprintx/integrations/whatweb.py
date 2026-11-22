"""WhatWeb wrapper."""

from __future__ import annotations

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class WhatWebIntegration(ToolIntegration):
    name = "whatweb"
    display_name = "WhatWeb"
    binary = "whatweb"
    version_args = ("--version",)
    install_hint = "apt install whatweb"

    def parse(self, output: str) -> list[Finding]:
        raise NotImplementedError
