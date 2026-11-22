"""Web technology detection (spec §5.6).

Built-in fingerprints (headers, cookies, HTML) always run against live websites;
WhatWeb adds its much larger plugin set when installed. HTTPx fingerprints come
from the http_probe module. Also reports version disclosure and missing security
headers as observations.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    observation,
)
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.whatweb import WhatWebIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import (
    fetch_in_scope,
    live_urls,
    locate,
    missing_tool_note,
    run_tool,
    skipped,
)
from footprintx.utils.fingerprints import fingerprint, missing_security_headers
from footprintx.utils.http import make_client
from footprintx.utils.ratelimit import RateLimiter

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class TechnologyDetectionModule(BaseModule):
    name = "technology_detection"
    description = "Fingerprint web servers, frameworks, CMSs, CDNs and security headers."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe",)
    integrations = ("whatweb", "httpx")
    active = True

    async def run(self, context: ScanContext) -> ModuleResult:
        urls = live_urls(context)
        if not urls:
            return skipped(self.name, "no live websites found")
        max_urls = int(self.config.option("max_urls", 100))
        urls = urls[:max_urls]

        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        result.findings.extend(await self._native(urls, context))

        whatweb = INTEGRATION_REGISTRY["whatweb"]
        assert isinstance(whatweb, WhatWebIntegration)
        path = locate(context, whatweb)
        if path is None:
            result.notes.append(missing_tool_note(whatweb) + " — built-in fingerprints only")
        else:
            input_file = context.save_raw("whatweb_input.txt", "\n".join(urls) + "\n")
            json_out = context.raw_dir / "whatweb.json"
            cmd = await run_tool(context, whatweb, path,
                                 whatweb.scan_args(str(input_file), str(json_out)),
                                 "whatweb_stdout.txt",
                                 timeout=context.settings.execution.module_timeout)
            text = json_out.read_text(encoding="utf-8", errors="replace") \
                if json_out.is_file() else ""
            found = whatweb.parse(text)
            if not found and not cmd.ok:
                result.errors.append(f"whatweb failed (exit {cmd.returncode})")
            for f in found:
                f.data["host"] = urlsplit(f.target or "").hostname or ""
            result.findings.extend(found)
        return result

    async def _native(self, urls: list[str], context: ScanContext) -> list[Finding]:
        settings = context.settings
        limiter = RateLimiter(settings.safety.max_requests_per_second)
        semaphore = asyncio.Semaphore(10)
        findings: list[Finding] = []

        async with make_client(settings.execution.timeout, follow_redirects=False) as client:
            async def inspect(url: str) -> None:
                async with semaphore:
                    await limiter.wait()
                    try:
                        response = await fetch_in_scope(client, url, context.scope)
                    except (httpx.HTTPError, ValueError):
                        return
                host = urlsplit(url).hostname or ""
                cookies = [c.split("=", 1)[0].strip()
                           for c in response.headers.get_list("set-cookie")]
                for tech in fingerprint(response.headers, cookies, response.text[:300_000]):
                    findings.append(Finding(
                        FindingKind.TECHNOLOGY, tech.name, self.name, url,
                        {"version": tech.version, "category": tech.category, "host": host}))

                disclosed = [f"{h}: {response.headers[h]}" for h in ("server", "x-powered-by")
                             if any(ch.isdigit() for ch in response.headers.get(h, ""))]
                if disclosed:
                    findings.append(observation(
                        "Software version disclosed in headers", url, self.name, "info",
                        "; ".join(disclosed)))
                missing = missing_security_headers(
                    response.headers, str(response.url).startswith("https://"))
                if missing:
                    findings.append(observation(
                        "Missing security headers", url, self.name, "info",
                        "Not set: " + ", ".join(missing)))

            await asyncio.gather(*(inspect(u) for u in urls))
        return findings
