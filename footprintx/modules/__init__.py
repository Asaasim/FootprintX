"""Reconnaissance modules and their registry.

Registry order is the default ordering inside each execution layer.
To add a module: create a package here, subclass BaseModule, register it below.
"""

from footprintx.core.config import Settings, did_you_mean
from footprintx.modules.base import BaseModule
from footprintx.modules.dns.module import DnsModule
from footprintx.modules.http_probe.module import HttpProbeModule
from footprintx.modules.ip_discovery.module import IpDiscoveryModule
from footprintx.modules.osint.module import OsintModule
from footprintx.modules.port_scanning.module import PortScanningModule
from footprintx.modules.proxy.module import ProxyModule
from footprintx.modules.shodan.module import ShodanModule
from footprintx.modules.subdomains.module import SubdomainModule
from footprintx.modules.technology_detection.module import TechnologyDetectionModule
from footprintx.modules.web_fuzzing.module import WebFuzzingModule

MODULE_REGISTRY: dict[str, type[BaseModule]] = {
    cls.name: cls
    for cls in (
    SubdomainModule,
    DnsModule,
    IpDiscoveryModule,
    HttpProbeModule,
    PortScanningModule,
    TechnologyDetectionModule,
    WebFuzzingModule,
    OsintModule,
    ShodanModule,
    ProxyModule,
    )
}



def module_config_warnings(settings: Settings) -> list[str]:
    """Unknown module names and misspelt module options in ``modules:``."""
    found: list[str] = []
    for name, config in settings.modules.items():
        cls = MODULE_REGISTRY.get(name)
        if cls is None:
            found.append(f"unknown module 'modules.{name}'"
                         f"{did_you_mean(name, list(MODULE_REGISTRY))} is ignored")
            continue
        valid = ["enabled", *sorted(cls.options)]
        for key in config.model_extra or {}:
            if key not in cls.options:
                found.append(f"unknown setting 'modules.{name}.{key}'"
                             f"{did_you_mean(key, valid)} is ignored")
    return found


__all__ = ["MODULE_REGISTRY", "BaseModule", "module_config_warnings"]
