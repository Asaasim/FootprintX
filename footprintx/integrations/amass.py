"""Amass wrapper (OWASP) — thorough but slow passive enumeration.

Amass output is not one-hostname-per-line in recent versions (it prints graph
relations such as ``a.example.com (FQDN) --> a_record --> 192.0.2.1``), so the
shared parser extracts every hostname under the target domain from the text.
"""

from __future__ import annotations

from footprintx.integrations.base import SubdomainToolIntegration


class AmassIntegration(SubdomainToolIntegration):
    name = "amass"
    display_name = "Amass"
    binaries = ("amass",)
    apt_package = "amass"
    version_args = ("-version",)
    install_hint = "go install -v github.com/owasp-amass/amass/v5/cmd/amass@main"

    def subdomain_args(self, domain: str) -> list[str]:
        return ["enum", "-passive", "-d", domain]
