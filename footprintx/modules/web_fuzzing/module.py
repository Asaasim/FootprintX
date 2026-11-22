"""Web fuzzing and content discovery (spec §5.7).

Runs FFUF (or Gobuster) with a wordlist against each live in-scope website and
flags sensitive discoveries — exposed .git/.env, backups, config files, admin
panels — as security observations.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from footprintx.core.models import (
    ALL_TARGET_TYPES,
    Finding,
    ModuleResult,
    ModuleStatus,
    observation,
)
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.ffuf import FfufIntegration
from footprintx.integrations.gobuster import GobusterIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import (
    active_proxy,
    base_url,
    live_urls,
    locate,
    missing_tool_note,
    skipped,
)
from footprintx.modules.common import run_tool as run_external
from footprintx.utils.helpers import safe_dirname
from footprintx.utils.wordlists import resolve_wordlist

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

DEFAULT_STATUS = [200, 204, 301, 302, 307, 401, 403]
#: Read-only methods only: fuzzing must never modify the target (spec §13.10).
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

#: (path regex, title, severity, statuses that count). First match wins.
SENSITIVE = [
    (r"(^|/)\.git(/|$)", "Exposed Git repository", "high", {200}),
    (r"(^|/)\.(svn|hg)(/|$)", "Exposed version-control directory", "high", {200}),
    (r"(^|/)\.env(\.|$)", "Exposed environment file (.env)", "high", {200}),
    (r"(^|/)(wp-config\.php\.?\w*|\.htpasswd|web\.config|config\.(json|ya?ml|php\.bak))$",
     "Configuration file exposed", "high", {200}),
    (r"\.(bak|old|backup|swp|sql|tar|tgz|gz|zip|7z|rar)$",
     "Backup or archive file exposed", "medium", {200}),
    (r"(^|/)(phpinfo|info)\.php$", "phpinfo() page exposed", "medium", {200}),
    (r"(^|/)server-(status|info)$", "Apache server status page exposed", "medium", {200}),
    (r"(^|/)(swagger(-ui)?|api-docs|openapi\.json|graphql)(/|$)",
     "API documentation or endpoint exposed", "info", {200}),
    (r"(^|/)(admin|administrator|wp-admin|wp-login\.php|phpmyadmin|manager|cpanel|"
     r"login|dashboard)(/|$)", "Administrative or login interface found", "info",
     {200, 401, 403}),
]
_SENSITIVE = [(re.compile(p, re.IGNORECASE), t, s, codes) for p, t, s, codes in SENSITIVE]


class WebFuzzingModule(BaseModule):
    name = "web_fuzzing"
    description = "Discover hidden directories, files and endpoints on live websites."
    applies_to = ALL_TARGET_TYPES
    depends_on = ("http_probe",)
    integrations = ("ffuf", "gobuster")
    active = True

    async def run(self, context: ScanContext) -> ModuleResult:
        bases = list(dict.fromkeys(base_url(u) for u in live_urls(context)))
        if not bases:
            return skipped(self.name, "no live websites found")

        wordlist = resolve_wordlist(self.config.option("wordlist"))
        if wordlist is None:
            configured = self.config.option("wordlist")
            return skipped(self.name, f"wordlist not found: {configured}" if configured else
                           "no wordlist found (sudo apt install seclists)")

        ffuf, gobuster = INTEGRATION_REGISTRY["ffuf"], INTEGRATION_REGISTRY["gobuster"]
        assert isinstance(ffuf, FfufIntegration) and isinstance(gobuster, GobusterIntegration)
        ffuf_path, gobuster_path = locate(context, ffuf), locate(context, gobuster)
        if not ffuf_path and not gobuster_path:
            return skipped(self.name,
                           f"{missing_tool_note(ffuf)}; {missing_tool_note(gobuster)}")

        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        max_targets = int(self.config.option("max_targets", 10))
        if len(bases) > max_targets:
            result.notes.append(f"{len(bases)} websites found; fuzzing the first {max_targets} "
                                "(raise modules.web_fuzzing.max_targets to fuzz more)")
            bases = bases[:max_targets]
        if not ffuf_path:
            result.notes.append(missing_tool_note(ffuf) + " — used Gobuster")
        result.notes.append(f"wordlist: {wordlist}")

        semaphore = asyncio.Semaphore(int(self.config.option("parallel", 2)))

        async def fuzz(base: str) -> list[Finding]:
            async with semaphore:
                if ffuf_path:
                    return await self._ffuf(ffuf, ffuf_path, base, str(wordlist), context)
                assert gobuster_path is not None
                return await self._gobuster(gobuster, gobuster_path, base, str(wordlist),
                                            context)

        outcomes = await asyncio.gather(*(fuzz(b) for b in bases), return_exceptions=True)
        for base, outcome in zip(bases, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                result.errors.append(f"{base}: {outcome}")
                continue
            for f in outcome:
                if context.scope.is_in_scope(f.value):
                    result.findings.append(f)
        result.findings += self._observations(result.findings)
        if result.errors and len(result.errors) == len(bases):
            result.status = ModuleStatus.FAILED
        return result

    def _options(self, context: ScanContext) -> dict:
        method = str(self.config.option("method", "GET")).upper()
        if method not in SAFE_METHODS:
            # Fuzzing with POST/PUT/DELETE could change data on the target (spec §13.10).
            method = "GET"
        return {
            "threads": int(self.config.option("threads", 40)),
            "timeout": int(context.settings.execution.timeout),
            "match_status": list(self.config.option("match_status", DEFAULT_STATUS)),
            "extensions": list(self.config.option("extensions", [])),
            "method": method,
            "proxy": active_proxy(context),
        }

    async def _ffuf(self, tool: FfufIntegration, path: str, base: str, wordlist: str,
                    context: ScanContext) -> list[Finding]:
        json_out = context.raw_dir / f"ffuf_{safe_dirname(base)}.json"
        rate = int(self.config.option("rate", context.settings.safety.max_requests_per_second))
        cmd = await run_external(
            context, tool, path,
            tool.fuzz_args(base, wordlist, str(json_out), rate=rate, **self._options(context)),
            f"ffuf_{safe_dirname(base)}_stdout.txt",
            timeout=float(self.config.option("target_timeout", 900)))
        text = json_out.read_text(encoding="utf-8", errors="replace") \
            if json_out.is_file() else ""
        findings = tool.parse(text, base)
        if not findings and not cmd.ok and not cmd.timed_out:
            last = (cmd.stderr.strip().splitlines() or ["no output"])[-1]
            raise RuntimeError(f"ffuf exit {cmd.returncode}: {last[:200]}")
        return findings

    async def _gobuster(self, tool: GobusterIntegration, path: str, base: str, wordlist: str,
                        context: ScanContext) -> list[Finding]:
        cmd = await run_external(
            context, tool, path, tool.fuzz_args(base, wordlist, **self._options(context)),
            f"gobuster_{safe_dirname(base)}.txt",
            timeout=float(self.config.option("target_timeout", 900)))
        findings = tool.parse(cmd.stdout, base)
        if not findings and not cmd.ok and not cmd.timed_out:
            last = (cmd.stderr.strip().splitlines() or ["no output"])[-1]
            raise RuntimeError(f"gobuster exit {cmd.returncode}: {last[:200]}")
        return findings

    @staticmethod
    def _observations(endpoints: list[Finding]) -> list[Finding]:
        found = []
        for f in endpoints:
            path = urlsplit(f.value).path.rstrip("/") or "/"
            status = int(f.data.get("status") or 0)
            for pattern, title, severity, codes in _SENSITIVE:
                if pattern.search(path) and status in codes:
                    detail = f"{f.value} returned HTTP {status}"
                    if status in (401, 403):
                        detail += " (exists, access restricted)"
                    found.append(observation(title, f.value, "web_fuzzing", severity, detail))
                    break
        return found
