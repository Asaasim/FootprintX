"""Web proxy integration (spec §5.10).

Sends every discovered in-scope URL and endpoint through Burp Suite or OWASP ZAP
so they show up in the proxy's site map for manual testing, and exports them to
``proxy_urls.txt``. Disabled by default; never blocks the rest of the scan.

With ``api: zap`` the module also uses ZAP's API (served on the proxy address):
it waits for ZAP's passive scanner to analyse the traffic it just sent, then
imports ZAP's alerts for in-scope URLs as observations (raw: ``raw/zap_alerts.json``).
ZAP's API key, if the API requires one, is read from ``ZAP_API_KEY`` in .env.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from footprintx.core.config import get_secret
from footprintx.core.models import (
    ALL_TARGET_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    observation,
)
from footprintx.modules.base import BaseModule
from footprintx.modules.common import skipped
from footprintx.utils.http import make_client
from footprintx.utils.ratelimit import RateLimiter

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

DEFAULT_PROXY = "http://127.0.0.1:8080"
DEFAULT_ZAP_WAIT = 60.0
DEFAULT_MAX_ALERTS = 1000
ZAP_PAGE = 500
ZAP_RISK = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}


class ZapApiError(RuntimeError):
    pass


class ProxyModule(BaseModule):
    name = "proxy"
    description = "Send discovered URLs through Burp Suite / OWASP ZAP for manual review."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe", "web_fuzzing")
    integrations = ()
    options = frozenset({"api", "max_alerts", "route_traffic", "url", "zap_wait"})
    enabled_by_default = False
    active = True

    async def run(self, context: ScanContext) -> ModuleResult:
        urls = [f.value for f in context.findings(FindingKind.URL) if f.data.get("live")]
        urls += [f.value for f in context.findings(FindingKind.ENDPOINT)]
        urls = [u for u in dict.fromkeys(urls) if context.scope.is_in_scope(u)]
        if not urls:
            return skipped(self.name, "no URLs discovered to send to the proxy")

        export = context.output_dir / "proxy_urls.txt"
        export.write_text("\n".join(urls) + "\n", encoding="utf-8")
        proxy = str(self.config.option("url", DEFAULT_PROXY))
        result = ModuleResult(self.name, ModuleStatus.SUCCESS,
                              notes=[f"exported {len(urls)} URLs to {export.name}"])

        limiter = RateLimiter(context.settings.safety.max_requests_per_second)
        semaphore = asyncio.Semaphore(10)
        sent = 0
        async with make_client(float(context.settings.execution.timeout), proxy=proxy,
                               follow_redirects=False) as client:
            try:
                await client.get(urls[0])
                sent += 1
            except (httpx.ProxyError, httpx.ConnectError):
                # Every connection goes to the proxy, so a connect failure means it is down.
                result.status = ModuleStatus.FAILED
                result.errors.append(f"proxy not reachable at {proxy} — is Burp/ZAP running?")
                return result
            except httpx.HTTPError:
                pass  # the target failed, not the proxy

            async def send(url: str) -> bool:
                async with semaphore:
                    await limiter.wait()
                    try:
                        await client.get(url)
                    except httpx.HTTPError:
                        return False
                    return True

            sent += sum(await asyncio.gather(*(send(u) for u in urls[1:])))
        result.notes.append(f"sent {sent} of {len(urls)} URLs through {proxy}")

        api = str(self.config.option("api", "none")).strip().lower()
        if api == "zap":
            await self._import_zap_alerts(proxy, urls, result, context)
        elif api not in ("none", ""):
            result.notes.append(f"proxy api {api!r} is not supported (use 'zap' or 'none')")
        return result

    # -- OWASP ZAP API ----------------------------------------------------------

    async def _import_zap_alerts(self, proxy: str, urls: list[str], result: ModuleResult,
                                 context: ScanContext) -> None:
        """Pull ZAP's passive-scan alerts for the URLs just sent. Problems become notes:
        the URLs already reached the proxy, the alerts are extra."""
        timeout = float(context.settings.execution.timeout)
        # The API is called directly, never through the proxy itself.
        async with make_client(timeout, follow_redirects=False) as api:
            key = get_secret("ZAP_API_KEY")
            if key:
                api.headers["X-ZAP-API-Key"] = key
            try:
                await self._wait_for_passive_scan(api, proxy)
                alerts = await self._zap_alerts(api, proxy, urls)
            except ZapApiError as exc:
                result.notes.append(f"ZAP API: {exc}")
                return
        context.save_raw("zap_alerts.json", json.dumps(alerts, indent=2))
        findings = zap_alerts_to_findings(alerts, context, self.name)
        result.findings.extend(findings)
        result.notes.append(f"imported {len(findings)} ZAP alerts")

    async def _zap_get(self, api: httpx.AsyncClient, proxy: str, path: str,
                       params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = await api.get(proxy.rstrip("/") + path, params=params)
        except httpx.HTTPError as exc:
            raise ZapApiError(f"not reachable at {proxy} ({type(exc).__name__})") from exc
        if response.status_code in (401, 403):
            raise ZapApiError("access denied - set ZAP_API_KEY in .env to the key shown in "
                              "ZAP under Tools > Options > API")
        if response.status_code != 200:
            raise ZapApiError(f"HTTP {response.status_code} from {path} - is this OWASP ZAP?")
        try:
            data = response.json()
        except ValueError as exc:
            raise ZapApiError(f"{path} did not return JSON - is this OWASP ZAP?") from exc
        if not isinstance(data, dict):
            raise ZapApiError(f"unexpected response from {path}")
        return data

    async def _wait_for_passive_scan(self, api: httpx.AsyncClient, proxy: str) -> None:
        deadline = time.monotonic() + float(self.config.option("zap_wait", DEFAULT_ZAP_WAIT))
        while True:
            data = await self._zap_get(api, proxy, "/JSON/pscan/view/recordsToScan/")
            try:
                remaining = int(data.get("recordsToScan", 0))
            except (TypeError, ValueError):
                remaining = 0
            if remaining <= 0 or time.monotonic() >= deadline:
                return
            await asyncio.sleep(1)

    async def _zap_alerts(self, api: httpx.AsyncClient, proxy: str,
                          urls: list[str]) -> list[dict[str, Any]]:
        limit = int(self.config.option("max_alerts", DEFAULT_MAX_ALERTS))
        origins = [o for o in dict.fromkeys(_origin(u) for u in urls) if o]
        alerts: list[dict[str, Any]] = []
        for origin in origins:
            start = 0
            while len(alerts) < limit:
                page = await self._zap_get(api, proxy, "/JSON/alert/view/alerts/", {
                    "baseurl": origin, "start": start,
                    "count": min(ZAP_PAGE, limit - len(alerts))})
                raw = page.get("alerts", [])
                items = [a for a in raw if isinstance(a, dict)] if isinstance(raw, list) else []
                alerts.extend(items)
                if len(items) < ZAP_PAGE:
                    break
                start += len(items)
        return alerts[:limit]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def zap_alerts_to_findings(alerts: list[dict[str, Any]], context: ScanContext,
                           source: str) -> list[Finding]:
    """ZAP alerts for in-scope URLs as observations, one per (alert, URL)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for alert in alerts:
        url = str(alert.get("url", ""))
        title = str(alert.get("alert") or alert.get("name") or "").strip()
        if not url or not title or (title, url) in seen or not context.scope.is_in_scope(url):
            continue
        seen.add((title, url))
        severity = ZAP_RISK.get(str(alert.get("risk", "")).lower(), "info")
        detail = " ".join(str(alert.get("description", "")).split())[:300]
        param = str(alert.get("param") or "")
        where = f"{url} (parameter {param})" if param else url
        finding = observation(f"ZAP: {title}", urlsplit(url).hostname or url, source,
                              severity, f"{where} - {detail}" if detail else where)
        finding.data.update({"url": url, "cwe": alert.get("cweid"),
                             "confidence": alert.get("confidence")})
        findings.append(finding)
    return findings
