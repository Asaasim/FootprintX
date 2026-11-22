"""OWASP ZAP API client."""

from __future__ import annotations

from footprintx.integrations.base import ApiIntegration


class ZapIntegration(ApiIntegration):
    name = "zap"
    display_name = "OWASP ZAP API"
    base_url = "http://127.0.0.1:8080"
    api_key_env = "ZAP_API_KEY"
    install_hint = "ZAP → Tools → Options → API → copy the API key"

    # TODO: async query methods using httpx.AsyncClient, honouring
    # safety.max_requests_per_second and failing gracefully (spec §5.9).
