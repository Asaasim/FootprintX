"""Web proxy integration (spec §5.10).

Sends every discovered in-scope URL and endpoint through Burp Suite or OWASP ZAP
so they show up in the proxy's site map for manual testing, and exports them to
``proxy_urls.txt``. Disabled by default; never blocks the rest of the scan.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import httpx

from footprintx.core.models import ALL_TARGET_TYPES, FindingKind, ModuleResult, ModuleStatus
from footprintx.modules.base import BaseModule
from footprintx.modules.common import skipped
from footprintx.utils.http import make_client
from footprintx.utils.ratelimit import RateLimiter

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

DEFAULT_PROXY = "http://127.0.0.1:8080"


class ProxyModule(BaseModule):
    name = "proxy"
    description = "Send discovered URLs through Burp Suite / OWASP ZAP for manual review."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe", "web_fuzzing")
    integrations = ()
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
        return result
