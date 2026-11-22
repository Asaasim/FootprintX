"""theHarvester wrapper — emails and hostnames from public sources (JSON output)."""

from __future__ import annotations

import json

from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ToolIntegration
from footprintx.utils.validators import hostnames_in

_EMAIL_OK = str.maketrans("", "", " <>\"'")


class TheHarvesterIntegration(ToolIntegration):
    name = "theharvester"
    display_name = "theHarvester"
    binaries = ("theHarvester", "theharvester")
    apt_package = "theharvester"
    version_args = ("-h",)
    install_hint = "pipx install theHarvester"

    def harvest_args(self, domain: str, sources: str, out_base: str, limit: int = 500
                     ) -> list[str]:
        """``-f out_base`` makes theHarvester write ``out_base.json`` (and ``.xml``)."""
        return ["-d", domain, "-b", sources, "-l", str(limit), "-f", out_base]

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        try:
            data = json.loads(output) if output.strip() else {}
        except ValueError:
            return []
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        domain = (target or "").lower()
        for raw in data.get("emails") or []:
            email = str(raw).translate(_EMAIL_OK).lower()
            if "@" in email and (not domain or email.endswith("@" + domain)
                                 or email.endswith("." + domain)):
                findings.append(Finding(FindingKind.EMAIL, email, self.name, target))
        hosts_text = "\n".join(str(h).split(":", 1)[0] for h in data.get("hosts") or [])
        for host in hostnames_in(hosts_text, domain or None):
            if host != domain:
                findings.append(Finding(FindingKind.SUBDOMAIN, host, self.name, target))
        return findings
