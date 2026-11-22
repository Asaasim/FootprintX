"""Subfinder wrapper (ProjectDiscovery) — passive subdomain enumeration."""

from __future__ import annotations

from footprintx.integrations.base import SubdomainToolIntegration


class SubfinderIntegration(SubdomainToolIntegration):
    name = "subfinder"
    display_name = "Subfinder"
    binaries = ("subfinder",)
    apt_package = "subfinder"
    version_args = ("-version",)
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    def subdomain_args(self, domain: str) -> list[str]:
        # -silent: hostnames only on stdout. API keys for extra sources go in
        # ~/.config/subfinder/provider-config.yaml (Subfinder's own config).
        return ["-d", domain, "-silent"]
