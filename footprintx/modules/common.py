"""Helpers modules use to pick their inputs from seed targets and earlier findings.

Every helper only returns in-scope assets, so active modules can't be pointed at
something outside the authorised scope by a stray DNS record or redirect.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from footprintx.core.models import FindingKind, ModuleResult, ModuleStatus, TargetType
from footprintx.core.process_manager import CommandResult, run_command
from footprintx.integrations.base import ToolIntegration

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext
    from footprintx.core.scope_manager import ScopeManager


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def scan_hostnames(context: ScanContext) -> list[str]:
    """Seed hostnames (domains, subdomains, URL hosts) plus discovered subdomains."""
    hosts: dict[str, None] = {}
    for t in context.targets:
        host = t.host
        if host and t.type is not TargetType.CIDR and not _is_ip(host):
            hosts[host] = None
    for f in context.findings(FindingKind.SUBDOMAIN):
        hosts[f.value] = None
    return [h for h in hosts if context.scope.is_in_scope(h)]


def resolved_hostnames(context: ScanContext) -> list[str]:
    """Hostnames that resolved in DNS — or all hostnames if DNS enumeration didn't run."""
    hosts = scan_hostnames(context)
    dns = context.results.get("dns")
    if dns is None or not dns.findings:
        return hosts
    resolved = {f.target for f in context.findings(FindingKind.IP_ADDRESS) if f.target}
    resolved |= {h for f in context.findings(FindingKind.IP_ADDRESS)
                 for h in f.data.get("hostnames", [])}
    return [h for h in hosts if h in resolved]


def scan_ips(context: ScanContext) -> list[str]:
    """In-scope IP addresses: seed IPs plus live hosts found in seed CIDR ranges.

    IPs that were merely resolved from hostnames are *not* included — they may
    belong to a CDN or hosting provider; those hosts are scanned by name instead.
    """
    ips: dict[str, None] = {}
    for t in context.targets:
        if t.type in (TargetType.IPV4, TargetType.IPV6):
            ips[t.value] = None
    for f in context.findings(FindingKind.IP_ADDRESS):
        if f.data.get("from_range") and f.data.get("reachable", True):
            ips[f.value] = None
    return [ip for ip in ips if context.scope.is_in_scope(ip)]


def all_known_ips(context: ScanContext) -> list[str]:
    """Every IP seen (seeds, ranges and DNS) — for passive lookups such as Shodan."""
    ips: dict[str, None] = dict.fromkeys(scan_ips(context))
    for f in context.findings(FindingKind.IP_ADDRESS):
        ips[f.value] = None
    return list(ips)


def live_urls(context: ScanContext) -> list[str]:
    """Base URLs that answered HTTP probing; seed URLs if probing didn't run."""
    urls: dict[str, None] = {}
    if context.results.get("http_probe") is not None:
        for f in context.findings(FindingKind.URL):
            if f.data.get("live"):
                urls[f.value] = None
    else:
        for t in context.targets:
            if t.type is TargetType.URL:
                urls[t.value] = None
    return [u for u in urls if context.scope.is_in_scope(u)]


async def fetch_in_scope(
    client: httpx.AsyncClient, url: str, scope: ScopeManager, max_redirects: int = 3
) -> httpx.Response:
    """GET ``url``, following redirects only while they stay inside the scope.

    ``client`` must be created with ``follow_redirects=False``.
    """
    response = await client.get(url)
    for _ in range(max_redirects):
        location = response.headers.get("location")
        if not response.is_redirect or not location:
            break
        next_url = str(response.url.join(location))
        if not scope.is_in_scope(next_url):
            break
        response = await client.get(next_url)
    return response


def base_url(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def host_of(value: str) -> str:
    return (urlsplit(value).hostname or "") if "://" in value else value


async def run_tool(
    context: ScanContext,
    tool: ToolIntegration,
    path: str,
    args: list[str],
    raw_name: str,
    timeout: float,
    cwd: Path | None = None,
) -> CommandResult:
    """Run an external tool, preserving its stdout under ``raw/raw_name``."""
    result = await run_command([path, *args], timeout=timeout, cwd=cwd)
    context.save_raw(raw_name, result.stdout if result.stdout else result.stderr)
    return result


def locate(context: ScanContext, tool: ToolIntegration) -> str | None:
    return tool.locate(context.settings.tools.paths.get(tool.name))


def missing_tool_note(tool: ToolIntegration) -> str:
    return f"{tool.display_name} not installed ({tool.installation_hint()})"


def skipped(module: str, reason: str) -> ModuleResult:
    return ModuleResult(module, ModuleStatus.SKIPPED, skip_reason=reason)
