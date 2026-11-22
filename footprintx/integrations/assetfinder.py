"""Assetfinder wrapper (tomnomnom) — passive subdomain discovery."""

from __future__ import annotations

from footprintx.integrations.base import SubdomainToolIntegration


class AssetfinderIntegration(SubdomainToolIntegration):
    name = "assetfinder"
    display_name = "Assetfinder"
    binaries = ("assetfinder",)
    apt_package = "assetfinder"
    version_args = ()  # assetfinder has no version flag
    install_hint = "go install github.com/tomnomnom/assetfinder@latest"

    def subdomain_args(self, domain: str) -> list[str]:
        return ["--subs-only", domain]
