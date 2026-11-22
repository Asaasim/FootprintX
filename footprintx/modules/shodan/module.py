"""Shodan integration (spec §5.9) — passive lookups of every discovered public IP.

Optional: without SHODAN_API_KEY the module is skipped and the scan continues.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

import httpx

from footprintx.core.models import (
    HOSTNAME_TYPES,
    IP_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    observation,
)
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.shodan import ShodanAuthError, ShodanIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import all_known_ips, skipped
from footprintx.utils.http import make_client
from footprintx.utils.ratelimit import RateLimiter

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class ShodanModule(BaseModule):
    name = "shodan"
    description = "Query Shodan for indexed ports, banners and vulnerability indicators."
    applies_to = HOSTNAME_TYPES | IP_TYPES
    depends_on = ("ip_discovery",)
    integrations = ("shodan",)

    async def run(self, context: ScanContext) -> ModuleResult:
        shodan = INTEGRATION_REGISTRY["shodan"]
        assert isinstance(shodan, ShodanIntegration)
        if not shodan.is_configured():
            return skipped(self.name, "no SHODAN_API_KEY configured (optional)")

        ips = [ip for ip in all_known_ips(context) if ipaddress.ip_address(ip).is_global]
        if not ips:
            return skipped(self.name, "no public IP addresses to look up")
        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        max_ips = int(self.config.option("max_ips", 100))
        if len(ips) > max_ips:
            result.notes.append(f"{len(ips)} IPs found; querying the first {max_ips}")
            ips = ips[:max_ips]

        # Free Shodan accounts allow about one request per second.
        limiter = RateLimiter(float(self.config.option("rate", 1)))
        indexed = 0
        async with make_client(max(float(context.settings.execution.timeout), 20.0),
                               verify=True) as client:
            for ip in ips:
                await limiter.wait()
                try:
                    data = await shodan.host(client, ip)
                except ShodanAuthError as exc:
                    result.status = ModuleStatus.FAILED
                    result.errors.append(str(exc))
                    return result
                except (httpx.HTTPError, RuntimeError, ValueError) as exc:
                    result.errors.append(f"{ip}: {(str(exc).splitlines() or ['error'])[0]}")
                    continue
                if data is None:
                    continue
                indexed += 1
                result.findings.extend(self._findings(ip, shodan.summarise(data)))

        result.notes.append(f"{indexed} of {len(ips)} IPs are indexed by Shodan")
        if result.errors and indexed == 0 and len(result.errors) == len(ips):
            result.status = ModuleStatus.FAILED
        return result

    def _findings(self, ip: str, info: dict) -> list[Finding]:
        findings = [Finding(FindingKind.INTEL, "Shodan host data", self.name, ip, info)]
        for svc in info["services"]:
            if not svc.get("port"):
                continue
            findings.append(Finding(
                FindingKind.OPEN_PORT, f"{ip}:{svc['port']}/{svc['transport']}", self.name, ip,
                {"host": ip, "ip": ip, "port": svc["port"], "protocol": svc["transport"],
                 "service": svc["module"], "product": svc["product"],
                 "version": svc["version"], "indexed": True}))
        if info["vulns"]:
            shown = ", ".join(info["vulns"][:20])
            more = f" (+{len(info['vulns']) - 20} more)" if len(info["vulns"]) > 20 else ""
            findings.append(observation(
                "Known vulnerabilities reported by Shodan", ip, self.name, "high",
                f"Shodan associates these CVEs with services on {ip}: {shown}{more}. "
                "Verify them manually — they are based on version banners."))
        return findings
