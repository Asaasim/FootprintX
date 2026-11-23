"""Subdomain discovery (spec §5.1).

Runs every configured, available source against each seed domain concurrently,
preserves raw output, and keeps only in-scope results. One failing source never
fails the module while another succeeds.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from footprintx.core.logger import get_logger
from footprintx.core.models import Finding, ModuleResult, ModuleStatus, TargetType
from footprintx.core.process_manager import run_command
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.base import SubdomainToolIntegration
from footprintx.integrations.crtsh import CrtShIntegration
from footprintx.modules.base import BaseModule
from footprintx.utils.helpers import safe_dirname

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

log = get_logger("modules.subdomains")

DEFAULT_SOURCES = ("subfinder", "assetfinder", "findomain", "crtsh")
DEFAULT_SOURCE_TIMEOUT = 600.0


class SourceError(RuntimeError):
    pass


class SubdomainModule(BaseModule):
    name = "subdomains"
    description = "Discover subdomains via passive sources and certificate transparency."
    applies_to = frozenset({TargetType.DOMAIN})
    depends_on = ()
    integrations = ("subfinder", "assetfinder", "findomain", "amass", "crtsh")
    options = frozenset({"source_timeout", "sources"})

    async def run(self, context: ScanContext) -> ModuleResult:
        result = ModuleResult(self.name)
        domains = sorted({t.value for t in context.targets if t.type is TargetType.DOMAIN})
        jobs: list[tuple[str, str, asyncio.Task[list[Finding]]]] = []

        for source in self.config.option("sources", list(DEFAULT_SOURCES)):
            integration = INTEGRATION_REGISTRY.get(source)
            if isinstance(integration, SubdomainToolIntegration):
                path = integration.locate(context.settings.tools.paths.get(source))
                if path is None:
                    result.notes.append(
                        f"{source} not installed ({integration.installation_hint()})")
                    continue
                for domain in domains:
                    jobs.append((source, domain, asyncio.create_task(
                        self._run_tool(integration, path, domain, context))))
            elif isinstance(integration, CrtShIntegration):
                for domain in domains:
                    jobs.append((source, domain, asyncio.create_task(
                        self._run_crtsh(integration, domain, context))))
            else:
                result.notes.append(f"unknown subdomain source {source!r} ignored")

        if not jobs:
            result.status = ModuleStatus.SKIPPED
            result.skip_reason = "no subdomain sources available"
            return result

        await asyncio.gather(*(task for _, _, task in jobs), return_exceptions=True)

        succeeded = 0
        out_of_scope: set[str] = set()
        for source, domain, task in jobs:
            exc = task.exception()
            if exc is not None:
                message = (str(exc).strip().splitlines() or [type(exc).__name__])[0]
                result.errors.append(f"{source} ({domain}): {message}")
                continue
            succeeded += 1
            for finding in task.result():
                if context.scope.is_in_scope(finding.value):
                    result.findings.append(finding)
                else:
                    out_of_scope.add(finding.value)

        if out_of_scope:
            result.notes.append(f"{len(out_of_scope)} out-of-scope hostnames discarded")
        result.status = ModuleStatus.SUCCESS if succeeded else ModuleStatus.FAILED
        log.info("subdomains: %d findings from %d/%d source runs",
                 len(result.findings), succeeded, len(jobs))
        return result

    def _source_timeout(self) -> float:
        return float(self.config.option("source_timeout", DEFAULT_SOURCE_TIMEOUT))

    async def _run_tool(
        self, tool: SubdomainToolIntegration, path: str, domain: str, context: ScanContext
    ) -> list[Finding]:
        cmd = await run_command([path, *tool.subdomain_args(domain)],
                                timeout=self._source_timeout())
        context.save_raw(f"{tool.name}_{safe_dirname(domain)}.txt", cmd.stdout)
        if cmd.timed_out:
            raise SourceError(f"timed out after {self._source_timeout():g}s")
        if cmd.returncode != 0 and not cmd.stdout.strip():
            last_line = (cmd.stderr.strip().splitlines() or ["no output"])[-1]
            raise SourceError(f"exit code {cmd.returncode}: {last_line[:200]}")
        return tool.parse(cmd.stdout, domain)

    async def _run_crtsh(
        self, client: CrtShIntegration, domain: str, context: ScanContext
    ) -> list[Finding]:
        settings = context.settings.execution
        raw = await client.fetch(domain, timeout=max(settings.timeout, 60),
                                 retries=settings.retries)
        context.save_raw(f"crtsh_{safe_dirname(domain)}.json", raw)
        return client.parse(raw, domain)
