"""crt.sh client — subdomains from Certificate Transparency logs (no API key)."""

from __future__ import annotations

import asyncio
import json

import httpx

from footprintx import __version__
from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ApiIntegration
from footprintx.utils.validators import hostnames_in


class CrtShIntegration(ApiIntegration):
    name = "crtsh"
    display_name = "crt.sh (CT logs)"
    base_url = "https://crt.sh/"
    api_key_env = None
    install_hint = "No credentials required"

    async def fetch(
        self, domain: str, *, timeout: float, retries: int, proxy: str | None = None
    ) -> str:
        """Raw JSON for every certificate matching ``*.domain``. crt.sh is often slow
        and returns 5xx under load, so failures are retried with backoff."""
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": f"FootprintX/{__version__}"}
        last_error: Exception | None = None
        async with httpx.AsyncClient(
            timeout=timeout, headers=headers, follow_redirects=True, proxy=proxy
        ) as client:
            for attempt in range(retries + 1):
                try:
                    response = await client.get(self.base_url, params=params)
                    response.raise_for_status()
                    return response.text
                except httpx.HTTPError as exc:
                    last_error = exc
                    if attempt < retries:
                        await asyncio.sleep(2**attempt)
        assert last_error is not None
        raise last_error

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        try:
            rows = json.loads(output) if output.strip() else []
        except ValueError:
            return []
        names = "\n".join(
            str(row.get("name_value", "")) for row in rows if isinstance(row, dict)
        )
        return [
            Finding(FindingKind.SUBDOMAIN, host, self.name, target)
            for host in hostnames_in(names, target)
            if host != target
        ]
