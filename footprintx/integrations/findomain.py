"""Findomain wrapper — subdomains from certificate transparency and other APIs."""

from __future__ import annotations

from footprintx.integrations.base import SubdomainToolIntegration


class FindomainIntegration(SubdomainToolIntegration):
    name = "findomain"
    display_name = "Findomain"
    binaries = ("findomain",)
    apt_package = "findomain"
    version_args = ("--version",)
    install_hint = "https://github.com/Findomain/Findomain/releases"

    def subdomain_args(self, domain: str) -> list[str]:
        return ["-t", domain, "-q"]  # -q: print only the subdomains
