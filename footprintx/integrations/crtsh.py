"""crt.sh (CT logs) client."""

from __future__ import annotations

from footprintx.integrations.base import ApiIntegration


class CrtShIntegration(ApiIntegration):
    name = "crtsh"
    display_name = "crt.sh (CT logs)"
    base_url = "https://crt.sh"
    api_key_env = None
    install_hint = "No credentials required"

    # TODO: async query methods using httpx.AsyncClient, honouring
    # safety.max_requests_per_second and failing gracefully (spec §5.9).
