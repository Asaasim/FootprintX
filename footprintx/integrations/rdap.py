"""RDAP client — domain registration and IP network ownership (public, no key).

rdap.org redirects each query to the authoritative registry's RDAP server.
"""

from __future__ import annotations

from typing import Any

import httpx

from footprintx.integrations.base import ApiIntegration
from footprintx.utils.http import make_client


class RdapIntegration(ApiIntegration):
    name = "rdap"
    display_name = "RDAP (registration data)"
    base_url = "https://rdap.org"
    api_key_env = None
    install_hint = "No credentials required"

    async def lookup(self, kind: str, value: str, *, timeout: float,
                     client: httpx.AsyncClient | None = None) -> dict[str, Any] | None:
        """``kind`` is "domain" or "ip". Returns None when the registry has no record."""
        owns_client = client is None
        client = client or make_client(timeout, verify=True)
        try:
            response = await client.get(f"{self.base_url}/{kind}/{value}")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            data = response.json()
        finally:
            if owns_client:
                await client.aclose()
        return data if isinstance(data, dict) else None

    @staticmethod
    def summarise_domain(data: dict[str, Any]) -> dict[str, Any]:
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])
                  if isinstance(e, dict)}
        return {
            "registrar": _entity_name(data, "registrar"),
            "registrant": _entity_name(data, "registrant"),
            "created": events.get("registration", ""),
            "expires": events.get("expiration", ""),
            "updated": events.get("last changed", ""),
            "nameservers": sorted({str(ns.get("ldhName", "")).lower()
                                   for ns in data.get("nameservers", []) if isinstance(ns, dict)}
                                  - {""}),
            "status": list(data.get("status", [])),
        }

    @staticmethod
    def summarise_ip(data: dict[str, Any]) -> dict[str, Any]:
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                 for c in data.get("cidr0_cidrs", []) if isinstance(c, dict)]
        return {
            "network_name": data.get("name", ""),
            "handle": data.get("handle", ""),
            "range": f"{data.get('startAddress', '')} - {data.get('endAddress', '')}",
            "cidrs": cidrs,
            "country": data.get("country", ""),
            "organisation": _entity_name(data, "registrant") or _entity_name(data, "abuse"),
        }


def _entity_name(data: dict[str, Any], role: str) -> str:
    for entity in data.get("entities", []):
        if not isinstance(entity, dict):
            continue
        if role in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return str(item[3])
            return str(entity.get("handle", ""))
        nested = _entity_name(entity, role)
        if nested:
            return nested
    return ""
