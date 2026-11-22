"""Live host and URL detection (spec §5.4).

Probes every resolved in-scope hostname, in-scope IP and seed URL over HTTP and
HTTPS. Uses httpx-toolkit when installed, otherwise a built-in prober; both yield
status, title, server, redirect target and size. TLS certificates are checked
natively for every HTTPS service.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

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
from footprintx.integrations.httpx import HttpxIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import (
    active_proxy,
    locate,
    missing_tool_note,
    resolved_hostnames,
    run_tool,
    scan_ips,
    skipped,
)
from footprintx.utils.http import fetch_limited, make_client
from footprintx.utils.ratelimit import RateLimiter
from footprintx.utils.tls import fetch_certificate

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HttpProbeModule(BaseModule):
    name = "http_probe"
    description = "Detect live websites: status, title, server, redirects, TLS certificates."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("ip_discovery",)
    integrations = ("httpx",)
    active = True

    async def run(self, context: ScanContext) -> ModuleResult:
        inputs = list(dict.fromkeys(
            [*resolved_hostnames(context), *scan_ips(context),
             *(t.value for t in context.targets if t.type is TargetType.URL)]))
        if not inputs:
            return skipped(self.name, "no reachable hosts or URLs to probe")

        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        settings = context.settings
        rate = int(self.config.option("rate", settings.safety.max_requests_per_second))
        threads = int(self.config.option("threads", 25))
        timeout = float(settings.execution.timeout)

        probes: list[dict[str, Any]] = []
        source = self.name
        proxy = active_proxy(context)
        tool = INTEGRATION_REGISTRY["httpx"]
        assert isinstance(tool, HttpxIntegration)
        path = locate(context, tool) if self.config.option("engine", "auto") != "native" else None
        if path is not None:
            input_file = context.save_raw("httpx_input.txt", "\n".join(inputs) + "\n")
            cmd = await run_tool(
                context, tool, path,
                tool.probe_args(str(input_file), threads=threads, rate=rate,
                                timeout=int(timeout), proxy=proxy),
                "httpx.jsonl", timeout=settings.execution.module_timeout)
            probes = tool.parse_probes(cmd.stdout)
            source = tool.name
            if not probes and not cmd.ok:
                result.notes.append(f"httpx-toolkit failed (exit {cmd.returncode}); "
                                    "used the built-in prober instead")
                path = None
        else:
            result.notes.append(missing_tool_note(tool) + " — used the built-in prober")

        if path is None:
            probes = await self._native_probe(inputs, rate, threads, timeout, proxy)
            source = self.name
            context.save_raw("http_probe.json", json.dumps(probes, indent=2))

        probes = [p for p in probes if context.scope.is_in_scope(p["host"])]
        tls = await self._check_tls(probes, timeout)
        result.findings = self._to_findings(probes, tls, source)
        result.notes.append(f"{len(probes)} live web services on "
                            f"{len({p['host'] for p in probes})} hosts")
        return result

    # -- probing ---------------------------------------------------------------

    async def _native_probe(self, inputs: list[str], rate: int, threads: int,
                            timeout: float, proxy: str | None = None
                            ) -> list[dict[str, Any]]:
        candidates: list[str] = []
        for item in inputs:
            if "://" in item:
                candidates.append(item)
            else:
                host = f"[{item}]" if _is_ipv6(item) else item
                candidates += [f"https://{host}", f"http://{host}"]

        limiter = RateLimiter(rate)
        semaphore = asyncio.Semaphore(threads)
        async with make_client(timeout, follow_redirects=False, proxy=proxy) as client:
            async def probe(url: str) -> dict[str, Any] | None:
                async with semaphore:
                    await limiter.wait()
                    try:
                        response = await fetch_limited(client, url)
                    except (httpx.HTTPError, ValueError):
                        return None
                parts = urlsplit(url)
                match = _TITLE.search(response.text[:200_000])
                return {
                    "url": url.rstrip("/"),
                    "host": parts.hostname or "",
                    "scheme": parts.scheme,
                    "port": parts.port or (443 if parts.scheme == "https" else 80),
                    "status_code": response.status_code,
                    "title": " ".join(html.unescape(match.group(1)).split())[:200]
                    if match else "",
                    "webserver": response.headers.get("server", ""),
                    "content_length": len(response.body),
                    "location": response.headers.get("location", ""),
                    "tech": [],
                    "ips": [],
                    "cdn": "",
                }

            found = await asyncio.gather(*(probe(u) for u in candidates))
        return [p for p in found if p]

    async def _check_tls(self, probes: list[dict[str, Any]],
                         timeout: float) -> dict[tuple[str, int], dict[str, Any]]:
        services = {(p["host"], int(p["port"])) for p in probes if p["scheme"] == "https"}
        semaphore = asyncio.Semaphore(20)

        async def check(host: str, port: int) -> tuple[tuple[str, int], dict[str, Any]]:
            async with semaphore:
                return (host, port), await asyncio.to_thread(fetch_certificate, host, port,
                                                             timeout)

        pairs = await asyncio.gather(*(check(h, p) for h, p in sorted(services)[:300]))
        return dict(pairs)

    # -- findings ----------------------------------------------------------------

    def _to_findings(self, probes: list[dict[str, Any]],
                     tls: dict[tuple[str, int], dict[str, Any]], source: str) -> list[Finding]:
        findings: list[Finding] = []
        schemes_by_host: dict[str, dict[str, dict[str, Any]]] = {}
        for p in probes:
            schemes_by_host.setdefault(p["host"], {})[p["scheme"]] = p
            data = {k: v for k, v in p.items() if k not in ("url", "host", "tech")}
            data["live"] = True
            cert = tls.get((p["host"], int(p["port"])))
            if cert:
                data["tls"] = cert
            findings.append(Finding(FindingKind.URL, p["url"], source, p["host"], data))
            findings.append(Finding(FindingKind.LIVE_HOST, p["host"], source, p["host"],
                                    {"urls": [p["url"]]}))
            for tech in p["tech"]:
                name, _, version = str(tech).partition(":")
                findings.append(Finding(FindingKind.TECHNOLOGY, name.strip(), source, p["url"],
                                        {"version": version.strip(), "host": p["host"]}))
            if str(p.get("title", "")).lower().startswith("index of /"):
                findings.append(observation(
                    "Directory listing enabled", p["url"], self.name, "medium",
                    "The web server lists directory contents, which can expose files."))

        for schemes in schemes_by_host.values():
            http = schemes.get("http")
            if http and "https" not in schemes and not _redirects_to_https(http):
                findings.append(observation(
                    "Website available only over plain HTTP", http["url"], self.name, "low",
                    "No HTTPS service answered; traffic to this site is unencrypted."))

        for (host, port), cert in tls.items():
            target = f"https://{host}" + ("" if port == 443 else f":{port}")
            if cert.get("valid") is False:
                findings.append(observation(
                    "Invalid TLS certificate", target, self.name, "low",
                    f"Certificate failed validation: {cert.get('error', 'unknown error')}"))
            elif cert.get("valid") and cert.get("days_left", 999) < 30:
                findings.append(observation(
                    "TLS certificate expires soon", target, self.name, "low",
                    f"Certificate expires in {cert['days_left']} days ({cert.get('not_after')})."))
        return findings


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _redirects_to_https(probe: dict[str, Any]) -> bool:
    status = probe.get("status_code") or 0
    return 300 <= int(status) < 400 and str(probe.get("location", "")).startswith("https://")
