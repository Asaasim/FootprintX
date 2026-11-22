"""Wrappers around external tools and intelligence APIs.

Modules refer to integrations by ``name``; ``footprintx doctor`` checks every entry here.
"""

from footprintx.integrations.amass import AmassIntegration
from footprintx.integrations.assetfinder import AssetfinderIntegration
from footprintx.integrations.base import ApiIntegration, Integration, ToolIntegration
from footprintx.integrations.crtsh import CrtShIntegration
from footprintx.integrations.ffuf import FfufIntegration
from footprintx.integrations.gobuster import GobusterIntegration
from footprintx.integrations.httpx import HttpxIntegration
from footprintx.integrations.naabu import NaabuIntegration
from footprintx.integrations.nmap import NmapIntegration
from footprintx.integrations.rdap import RdapIntegration
from footprintx.integrations.shodan import ShodanIntegration
from footprintx.integrations.subfinder import SubfinderIntegration
from footprintx.integrations.theharvester import TheHarvesterIntegration
from footprintx.integrations.whatweb import WhatWebIntegration

INTEGRATION_REGISTRY: dict[str, Integration] = {
    i.name: i
    for i in (
        SubfinderIntegration(),
        AssetfinderIntegration(),
        AmassIntegration(),
        HttpxIntegration(),
        NmapIntegration(),
        NaabuIntegration(),
        WhatWebIntegration(),
        FfufIntegration(),
        GobusterIntegration(),
        TheHarvesterIntegration(),
        CrtShIntegration(),
        RdapIntegration(),
        ShodanIntegration(),
    )
}

__all__ = ["INTEGRATION_REGISTRY", "ApiIntegration", "Integration", "ToolIntegration"]
