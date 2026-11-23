"""crt.sh client — subdomains from Certificate Transparency logs (no API key)."""

from __future__ import annotations

import asyncio
import json

import httpx

from footprintx import __version__
from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ApiIntegration
from footprintx.utils.validators import hostnames_in


class CrtShError(RuntimeError):
    """crt.sh could not be queried; the message is meant for the person running the scan."""


def _describe(error: Exception | None, attempts: int) -> str:
    tries = f"after {attempts} attempts"
    if isinstance(error, httpx.HTTPStatusError):
        return (f"crt.sh is temporarily unavailable (HTTP {error.response.status_code} "
                f"{tries}) - this is a problem on crt.sh's side, try again later")
    if isinstance(error, httpx.TimeoutException):
        return f"crt.sh did not respond in time ({tries}) - it is often overloaded, try later"
    return f"could not reach crt.sh ({tries}): {error}"


class CrtShIntegration(ApiIntegration):
    name = "crtsh"
    display_name = "crt.sh (CT logs)"
    base_url = "https://crt.sh/"
    api_key_env = None
    install_hint = "No credentials required"

    #: crt.sh outages are usually short: wait 3, 6, 12 … seconds between attempts.
    min_attempts = 4
    backoff = 3.0

    async def fetch(
        self, domain: str, *, timeout: float, retries: int, proxy: str | None = None
    ) -> str:
        """Raw JSON for every certificate matching ``*.domain``. crt.sh is often slow
        and returns 5xx under load, so failures are retried with backoff."""
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": f"FootprintX/{__version__}"}
        attempts = max(retries + 1, self.min_attempts)
        last_error: Exception | None = None
        async with httpx.AsyncClient(
            timeout=timeout, headers=headers, follow_redirects=True, proxy=proxy
        ) as client:
            for attempt in range(attempts):
                try:
                    response = await client.get(self.base_url, params=params)
                    response.raise_for_status()
                    return response.text
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code < 500 and exc.response.status_code != 429:
                        raise CrtShError(f"crt.sh refused the request (HTTP "
                                         f"{exc.response.status_code})") from exc
                    last_error = exc
                except httpx.HTTPError as exc:
                    last_error = exc
                if attempt < attempts - 1:
                    await asyncio.sleep(self.backoff * 2**attempt)
        raise CrtShError(_describe(last_error, attempts)) from last_error

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
