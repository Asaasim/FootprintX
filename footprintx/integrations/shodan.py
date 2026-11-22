"""Shodan API client — indexed ports, banners and vulnerability indicators.

The API key travels in the query string (Shodan's only option), so httpx's own
error messages — which include the full URL — must never be surfaced. Errors are
re-raised with messages that contain only the status code.
"""

from __future__ import annotations

from typing import Any

import httpx

from footprintx.integrations.base import ApiIntegration
from footprintx.utils.http import RetryableHTTPError, get_with_retries


class ShodanAuthError(RuntimeError):
    pass


class ShodanError(RuntimeError):
    pass


class ShodanIntegration(ApiIntegration):
    name = "shodan"
    display_name = "Shodan API"
    base_url = "https://api.shodan.io"
    api_key_env = "SHODAN_API_KEY"
    install_hint = "Create a free account at https://account.shodan.io and copy the API key"

    async def host(self, client: httpx.AsyncClient, ip: str, retries: int = 2
                   ) -> dict[str, Any] | None:
        """Shodan's record for ``ip``; None if Shodan has never indexed it."""
        try:
            response = await get_with_retries(
                client, f"{self.base_url}/shodan/host/{ip}",
                params={"key": self.api_key() or ""}, retries=retries)
        except RetryableHTTPError as exc:
            raise ShodanError(f"Shodan unavailable (HTTP {exc.status_code})") from None
        except httpx.HTTPError as exc:
            # str(exc) may contain the request URL — and with it the API key.
            raise ShodanError(f"Shodan request failed ({type(exc).__name__})") from None
        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            raise ShodanAuthError("Shodan rejected the API key (check SHODAN_API_KEY)")
        if response.status_code >= 400:
            raise ShodanError(f"Shodan returned HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError:
            raise ShodanError("Shodan returned an invalid response") from None
        return data if isinstance(data, dict) else None

    @staticmethod
    def summarise(data: dict[str, Any]) -> dict[str, Any]:
        vulns = data.get("vulns") or []
        if isinstance(vulns, dict):
            vulns = list(vulns)
        services = []
        for banner in data.get("data") or []:
            if not isinstance(banner, dict):
                continue
            services.append({
                "port": banner.get("port"),
                "transport": banner.get("transport", "tcp"),
                "product": banner.get("product", ""),
                "version": banner.get("version", ""),
                "module": (banner.get("_shodan") or {}).get("module", ""),
            })
        return {
            "organisation": data.get("org", ""),
            "isp": data.get("isp", ""),
            "asn": data.get("asn", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "os": data.get("os") or "",
            "hostnames": list(data.get("hostnames") or []),
            "ports": sorted(data.get("ports") or []),
            "vulns": sorted(str(v) for v in vulns),
            "last_update": data.get("last_update", ""),
            "services": services,
        }
