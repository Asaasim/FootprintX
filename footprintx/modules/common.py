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
from footprintx.utils.http import Page, fetch_limited
from footprintx.utils.platform import system_resolvers

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


def host_addresses(context: ScanContext) -> dict[str, set[str]]:
    """hostname → every IP address it resolved to."""
    mapping: dict[str, set[str]] = {}
    for f in context.findings(FindingKind.IP_ADDRESS):
        for host in {*(f.data.get("hostnames") or []), *([f.target] if f.target else [])}:
            if not _is_ip(host):
                mapping.setdefault(host, set()).add(f.value)
    return mapping


def address_risk(ip: str) -> str | None:
    """Why an address must not be probed because a *name* pointed at it, or None.

    - "local": loopback, link-local (incl. the 169.254.169.254 cloud metadata
      service), unspecified or multicast — probing these hits the scanning machine
      or its environment, never the target.
    - "internal": any other non-public address (RFC 1918, CGNAT, reserved).
    """
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        return "local"
    if not addr.is_global:
        return "internal"
    return None


def internal_hosts(context: ScanContext) -> dict[str, str]:
    """Hostnames that resolve only to local/internal addresses and are therefore not
    actively scanned, with the reason. Addresses explicitly in the scope (an IP or
    range target, or ``scope.include``) are always allowed; internal (not local)
    addresses are allowed with ``safety.allow_internal_targets``."""
    allow_internal = context.settings.safety.allow_internal_targets
    blocked: dict[str, str] = {}
    for host, ips in host_addresses(context).items():
        risks = []
        for ip in ips:
            risk = address_risk(ip)
            allowed = (risk is None
                       or context.scope.explicitly_includes(ip)
                       or (risk == "internal" and allow_internal))
            risks.append(None if allowed else risk)
        if risks and all(risks):
            blocked[host] = "local" if "local" in risks else "internal"
    return blocked


def resolved_hostnames(context: ScanContext) -> list[str]:
    """Hostnames that resolved in DNS (or all hostnames if DNS enumeration didn't
    run), minus those that only point at local/internal addresses."""
    hosts = scan_hostnames(context)
    dns = context.results.get("dns")
    if dns is not None and dns.findings:
        resolved = host_addresses(context)
        hosts = [h for h in hosts if h in resolved]
    blocked = internal_hosts(context)
    return [h for h in hosts if h not in blocked]


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
) -> Page:
    """GET ``url`` (body size-limited), following redirects only while they stay
    inside the scope. ``client`` must be created with ``follow_redirects=False``."""
    page = await fetch_limited(client, url)
    for _ in range(max_redirects):
        if not page.is_redirect:
            break
        next_url = str(page.url.join(page.headers["location"]))
        if not scope.is_in_scope(next_url):
            break
        page = await fetch_limited(client, next_url)
    return page


def dns_resolvers(context: ScanContext) -> list[str]:
    """Resolvers external tools should use: ``modules.dns.resolvers`` if set, else the
    system's — so every tool sees the same DNS as FootprintX's own lookups."""
    configured = context.settings.module_config("dns").option("resolvers") or []
    return [str(r) for r in configured] or system_resolvers()


def active_proxy(context: ScanContext) -> str | None:
    """Proxy URL for active HTTP traffic when ``modules.proxy.route_traffic`` is on
    (spec §5.10: route requests through Burp Suite / ZAP for inspection)."""
    config = context.settings.module_config("proxy", enabled_by_default=False)
    if config.enabled and config.option("route_traffic", False):
        return str(config.option("url", "http://127.0.0.1:8080"))
    return None


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
