"""OSINT and external intelligence (spec §5.8).

Passive only: RDAP registration data for seed domains and network ownership for
seed IPs, plus theHarvester (when installed) for public email addresses and
additional hostnames. Every finding keeps its source.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import tldextract

from footprintx.core.models import (
    HOSTNAME_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    TargetType,
    observation,
)
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.rdap import RdapIntegration
from footprintx.integrations.theharvester import TheHarvesterIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import locate, missing_tool_note, run_tool
from footprintx.utils.helpers import safe_dirname
from footprintx.utils.http import make_client

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

_extract = tldextract.TLDExtract(suffix_list_urls=())
DEFAULT_HARVESTER_SOURCES = "crtsh,hackertarget,rapiddns,otx,urlscan"


class OsintModule(BaseModule):
    name = "osint"
    description = "Public intelligence: domain registration, IP ownership, emails, hosts."
    applies_to = HOSTNAME_TYPES | {TargetType.IPV4, TargetType.IPV6}
    depends_on = ()
    integrations = ("rdap", "theharvester")
    options = frozenset({"harvester_sources", "harvester_timeout"})

    async def run(self, context: ScanContext) -> ModuleResult:
        domains = sorted({_registered(t.value) for t in context.targets
                          if t.type in HOSTNAME_TYPES} - {""})
        ips = [t.value for t in context.targets if t.type in (TargetType.IPV4, TargetType.IPV6)]
        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        rdap = INTEGRATION_REGISTRY["rdap"]
        assert isinstance(rdap, RdapIntegration)
        timeout = max(float(context.settings.execution.timeout), 20.0)

        async with make_client(timeout, verify=True) as client:
            lookups = [self._rdap_domain(rdap, d, client, timeout) for d in domains]
            lookups += [self._rdap_ip(rdap, ip, client, timeout) for ip in ips[:50]]
            outcomes = await asyncio.gather(*lookups, return_exceptions=True)
        for subject, outcome in zip([*domains, *ips[:50]], outcomes, strict=True):
            if isinstance(outcome, BaseException):
                result.notes.append(f"RDAP lookup for {subject} failed: "
                                    f"{(str(outcome).splitlines() or [type(outcome).__name__])[0]}")
            else:
                result.findings.extend(outcome)

        apexes = sorted({t.value for t in context.targets if t.type is TargetType.DOMAIN})
        if apexes:
            result.findings.extend(await self._harvest(apexes, context, result))
        result.findings = [f for f in result.findings
                           if f.kind is not FindingKind.SUBDOMAIN
                           or context.scope.is_in_scope(f.value)]
        return result

    async def _rdap_domain(self, rdap: RdapIntegration, domain: str, client, timeout: float
                           ) -> list[Finding]:
        data = await rdap.lookup("domain", domain, timeout=timeout, client=client)
        if data is None:
            return []
        info = rdap.summarise_domain(data)
        findings = [Finding(FindingKind.INTEL, "Domain registration", rdap.name, domain, info)]
        expires = _parse_date(info.get("expires", ""))
        if expires is not None:
            days = (expires - datetime.now(UTC)).days
            if 0 <= days < 30:
                findings.append(observation(
                    "Domain registration expires soon", domain, self.name, "medium",
                    f"{domain} expires in {days} days ({info['expires']}). An expired domain "
                    "can be registered by someone else."))
        return findings

    async def _rdap_ip(self, rdap: RdapIntegration, ip: str, client, timeout: float
                       ) -> list[Finding]:
        data = await rdap.lookup("ip", ip, timeout=timeout, client=client)
        if data is None:
            return []
        return [Finding(FindingKind.INTEL, "Network ownership", rdap.name, ip,
                        rdap.summarise_ip(data))]

    async def _harvest(self, domains: list[str], context: ScanContext, result: ModuleResult
                       ) -> list[Finding]:
        tool = INTEGRATION_REGISTRY["theharvester"]
        assert isinstance(tool, TheHarvesterIntegration)
        path = locate(context, tool)
        if path is None:
            result.notes.append(missing_tool_note(tool) + " — no email harvesting")
            return []
        sources = str(self.config.option("harvester_sources", DEFAULT_HARVESTER_SOURCES))
        findings: list[Finding] = []
        for domain in domains:
            # theHarvester drops the directory part of -f, cuts the name at the first dot
            # and writes into its working directory — so run it inside raw/ with a
            # dot-free name.
            out_name = "theharvester_" + safe_dirname(domain).replace(".", "_")
            cmd = await run_tool(context, tool, path,
                                 tool.harvest_args(domain, sources, out_name),
                                 f"{out_name}_stdout.txt",
                                 timeout=float(self.config.option("harvester_timeout", 600)),
                                 cwd=context.raw_dir)
            json_file = context.raw_dir / f"{out_name}.json"
            text = json_file.read_text(encoding="utf-8", errors="replace") \
                if json_file.is_file() else ""
            found = tool.parse(text, domain)
            if not found and not cmd.ok:
                result.notes.append(f"theHarvester failed for {domain} (exit {cmd.returncode})")
            findings.extend(found)
        return findings


def _registered(host: str | None) -> str:
    if not host:
        return ""
    parts = _extract(host)
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else host


def _parse_date(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
