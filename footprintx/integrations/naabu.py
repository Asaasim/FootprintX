"""Naabu wrapper (ProjectDiscovery) — fast port discovery (JSON lines output)."""

from __future__ import annotations

import json

from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ToolIntegration


class NaabuIntegration(ToolIntegration):
    name = "naabu"
    display_name = "Naabu"
    binaries = ("naabu",)
    apt_package = "naabu"
    version_args = ("-version",)
    install_hint = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

    def port_scan_args(self, targets_file: str, *, top_ports: int, rate: int,
                       raw_sockets: bool, ports: list[int] | None = None) -> list[str]:
        if ports:
            port_args = ["-p", ",".join(map(str, ports))]
        else:
            # naabu only accepts the presets 100, 1000 or full for -top-ports.
            preset = "100" if top_ports <= 100 else "1000" if top_ports <= 1000 else "full"
            port_args = ["-top-ports", preset]
        return [
            "-list", targets_file, "-json", "-silent", "-nc", *port_args,
            "-rate", str(rate), "-scan-type", "s" if raw_sockets else "c",
        ]

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            port = row.get("port")
            if isinstance(port, dict):  # some versions nest {"Port": 80, "Protocol": ...}
                port = port.get("Port") or port.get("port")
            if not port:
                continue
            host = row.get("host") or row.get("ip", "")
            protocol = str(row.get("protocol") or "tcp").lower()
            findings.append(Finding(
                FindingKind.OPEN_PORT, f"{host}:{port}/{protocol}", self.name, host,
                {"host": host, "ip": row.get("ip", ""), "port": int(port),
                 "protocol": protocol, "service": "", "product": "", "version": ""}))
        return findings
