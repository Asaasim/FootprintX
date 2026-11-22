"""Shodan API client — indexed ports, banners and vulnerability indicators."""

from __future__ import annotations

from typing import Any

import httpx

from footprintx.integrations.base import ApiIntegration


class ShodanAuthError(RuntimeError):
    pass


class ShodanIntegration(ApiIntegration):
    name = "shodan"
    display_name = "Shodan API"
    base_url = "https://api.shodan.io"
    api_key_env = "SHODAN_API_KEY"
    install_hint = "Create a free account at https://account.shodan.io and copy the API key"

    async def host(self, client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
        """Shodan's record for ``ip``; None if Shodan has never indexed it."""
        response = await client.get(f"{self.base_url}/shodan/host/{ip}",
                                    params={"key": self.api_key() or ""})
        if response.status_code == 404:
            return None
        if response.status_code in (401, 403):
            raise ShodanAuthError("Shodan rejected the API key (check SHODAN_API_KEY)")
        if response.status_code == 429:
            raise RuntimeError("Shodan rate limit reached")
        response.raise_for_status()
        data = response.json()
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
