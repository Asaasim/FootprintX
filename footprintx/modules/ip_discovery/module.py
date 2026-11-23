"""IP discovery and enumeration (spec §5.3).

Builds the IP ↔ hostname map from DNS, adds seed IPs, expands authorised CIDR
ranges (with an Nmap ping sweep to find live hosts when available) and looks up
reverse DNS (PTR) names.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.reversename

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    TargetType,
    observation,
)
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.nmap import NmapIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import (
    host_addresses,
    internal_hosts,
    locate,
    missing_tool_note,
    run_tool,
)
from footprintx.utils.helpers import safe_dirname

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

DEFAULT_MAX_RANGE_HOSTS = 1024
MAX_PTR_LOOKUPS = 512


class IpDiscoveryModule(BaseModule):
    name = "ip_discovery"
    description = "Map hostnames to IPs, expand authorised ranges, find live hosts, reverse DNS."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("dns",)
    integrations = ("nmap",)
    options = frozenset({"max_range_hosts"})

    async def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        ips: dict[str, dict] = {}

        def add(ip: str, **data: object) -> dict:
            entry = ips.setdefault(ip, {"hostnames": set()})
            for key, value in data.items():
                if key == "hostnames":
                    entry["hostnames"].update(value)
                else:
                    entry[key] = value
            return entry

        for f in context.findings(FindingKind.IP_ADDRESS):
            hostnames = f.data.get("hostnames") or ([f.target] if f.target else [])
            add(f.value, hostnames=hostnames)

        for t in context.targets:
            if t.type in (TargetType.IPV4, TargetType.IPV6):
                add(t.value, seed=True)

        for t in context.targets:
            if t.type is TargetType.CIDR:
                await self._expand_range(t.value, context, result, add)

        await self._reverse_dns(ips, context)

        for ip, entry in ips.items():
            version = ipaddress.ip_address(ip).version
            data = {
                "hostnames": sorted(entry["hostnames"]),
                "version": version,
                "private": ipaddress.ip_address(ip).is_private,
            }
            for key in ("reverse_dns", "from_range", "reachable", "seed"):
                if key in entry:
                    data[key] = entry[key]
            result.findings.append(Finding(FindingKind.IP_ADDRESS, ip, self.name, None, data))

        self._report_internal_names(context, result)
        return result

    def _report_internal_names(self, context: ScanContext, result: ModuleResult) -> None:
        """Names that only point at internal/local addresses: reported, not scanned."""
        # ``internal_hosts`` reads findings from finished modules; this module's own
        # findings aren't recorded yet, so the DNS data it uses is complete already.
        blocked = internal_hosts(context)
        if not blocked:
            return
        addresses = host_addresses(context)
        for host, risk in sorted(blocked.items()):
            ips = ", ".join(sorted(addresses.get(host, ())))
            if risk == "local":
                result.findings.append(observation(
                    "Hostname points to a loopback or link-local address", host, self.name,
                    "low", f"{host} resolves to {ips}. Not scanned: probing it would hit "
                    "the scanning machine or its cloud metadata service, not the target."))
            else:
                result.findings.append(observation(
                    "Public DNS reveals an internal address", host, self.name, "low",
                    f"{host} resolves to the internal address {ips}, disclosing details "
                    "of the internal network."))
        internal = sum(1 for r in blocked.values() if r == "internal")
        if internal:
            result.notes.append(
                f"{internal} host(s) resolve only to internal addresses and were not actively "
                "scanned — use --allow-internal if they are part of the authorised test")
        local = len(blocked) - internal
        if local:
            result.notes.append(f"{local} host(s) resolve to loopback/link-local addresses "
                                "and are never scanned")

    async def _expand_range(self, cidr: str, context: ScanContext, result: ModuleResult,
                            add) -> None:
        network = ipaddress.ip_network(cidr, strict=False)
        limit = int(self.config.option("max_range_hosts", DEFAULT_MAX_RANGE_HOSTS))
        if network.num_addresses > limit:
            result.errors.append(
                f"{cidr} has {network.num_addresses} addresses (limit {limit}); not expanded. "
                "Raise modules.ip_discovery.max_range_hosts to allow it.")
            return
        if context.passive:
            result.notes.append(f"{cidr}: live-host sweep skipped in passive mode")
            return

        hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]
        nmap = INTEGRATION_REGISTRY["nmap"]
        assert isinstance(nmap, NmapIntegration)
        path = locate(context, nmap)
        if path is None:
            result.notes.append(f"{missing_tool_note(nmap)} — all {len(hosts)} addresses in "
                                f"{cidr} kept without a live-host check")
            for ip in hosts:
                add(ip, from_range=True)
            return

        cmd = await run_tool(context, nmap, path, nmap.sweep_args([cidr]),
                             f"nmap_sweep_{safe_dirname(cidr)}.xml",
                             timeout=context.settings.execution.module_timeout)
        live = set(nmap.parse_sweep(cmd.stdout))
        if not cmd.ok and not live:
            reason = (cmd.stderr.strip().splitlines() or cmd.stdout.strip().splitlines()
                      or [f"exit {cmd.returncode}"])[-1]
            result.errors.append(f"nmap sweep of {cidr} failed: {reason[:200]}")
            result.notes.append(f"all {len(hosts)} addresses in {cidr} kept without a "
                                "live-host check")
            for ip in hosts:
                add(ip, from_range=True)
            return
        result.notes.append(f"{cidr}: {len(live)} of {len(hosts)} hosts up")
        for ip in hosts:
            if ip in live:
                add(ip, from_range=True, reachable=True)

    async def _reverse_dns(self, ips: dict[str, dict], context: ScanContext) -> None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = float(context.settings.execution.timeout)
        semaphore = asyncio.Semaphore(50)

        async def lookup(ip: str) -> None:
            async with semaphore:
                try:
                    answer = await resolver.resolve(dns.reversename.from_address(ip), "PTR")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    return
                names = [r.to_text().rstrip(".").lower() for r in answer]
                if names:
                    ips[ip]["reverse_dns"] = names

        await asyncio.gather(*(lookup(ip) for ip in list(ips)[:MAX_PTR_LOOKUPS]))
