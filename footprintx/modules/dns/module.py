"""DNS enumeration (spec §5.2)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    HOSTNAME_TYPES,
    ModuleResult,
    TargetType,
)
from footprintx.modules.base import BaseModule

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class DnsModule(BaseModule):
    name = "dns"
    description = "Enumerate A/AAAA/CNAME/MX/NS/TXT/SOA/PTR/CAA records."
    applies_to = HOSTNAME_TYPES | {TargetType.URL}
    depends_on = ("subdomains",)
    integrations = ("dnsx",)

    async def run(self, context: ScanContext) -> ModuleResult:
        raise NotImplementedError
