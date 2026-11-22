"""Shodan API client."""

from __future__ import annotations

from footprintx.integrations.base import ApiIntegration


class ShodanIntegration(ApiIntegration):
    name = "shodan"
    display_name = "Shodan API"
    base_url = "https://api.shodan.io"
    api_key_env = "SHODAN_API_KEY"
    install_hint = "Create a free account at https://account.shodan.io and copy the API key"

    # TODO: async query methods using httpx.AsyncClient, honouring
    # safety.max_requests_per_second and failing gracefully (spec §5.9).
