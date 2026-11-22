"""Nmap wrapper — host discovery sweeps and port/service scans (XML output)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ToolIntegration

NMAP_SERVICES = (
    "/usr/share/nmap/nmap-services",          # Kali / Debian
    "/usr/local/share/nmap/nmap-services",    # source installs
    "/opt/homebrew/share/nmap/nmap-services", # macOS Homebrew
)


class NmapIntegration(ToolIntegration):
    name = "nmap"
    display_name = "Nmap"
    binaries = ("nmap",)
    apt_package = "nmap"
    version_args = ("--version",)
    install_hint = "apt install nmap  (or https://nmap.org/download)"

    def sweep_args(self, ranges: list[str]) -> list[str]:
        """Ping sweep: which hosts in these ranges are up (no port scan, no DNS)."""
        return ["-sn", "-n", "-T4", "-oX", "-", *ranges]

    def port_scan_args(
        self, targets_file: str, xml_out: str, *, top_ports: int, raw_sockets: bool,
        ports: list[int] | None = None, service_detection: bool = True,
        host_timeout: str = "15m",
    ) -> list[str]:
        """``ports`` (explicit list) takes precedence over ``--top-ports``."""
        port_args = (["-p", "T:" + ",".join(map(str, ports))] if ports
                     else ["--top-ports", str(top_ports)])
        return [
            "-sS" if raw_sockets else "-sT",
            *(["-sV", "--version-light"] if service_detection else []),
            "-Pn", "-T4", "--open", *port_args,
            "--host-timeout", host_timeout,
            "-iL", targets_file, "-oX", xml_out,
        ]

    @staticmethod
    def top_tcp_ports(count: int, services_files: tuple[str, ...] = NMAP_SERVICES
                      ) -> list[int] | None:
        """The ``count`` most common TCP ports, from nmap's own frequency table.

        Used to scan "top N plus the risky services" — several high-risk services
        (Redis 6379, MongoDB 27017, Elasticsearch 9200) are outside nmap's top 1000.
        Returns None if the table isn't available.
        """
        for candidate in services_files:
            path = Path(candidate)
            if not path.is_file():
                continue
            ranked: list[tuple[float, int]] = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 3 or not parts[1].endswith("/tcp"):
                    continue
                try:
                    ranked.append((float(parts[2]), int(parts[1].split("/")[0])))
                except ValueError:
                    continue
            ranked.sort(reverse=True)
            return [port for _, port in ranked[:count]]
        return None

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        """Open ports from ``-oX`` output, one OPEN_PORT finding per host/port."""
        findings: list[Finding] = []
        for host in _hosts(output):
            for port in host["ports"]:
                findings.append(Finding(
                    FindingKind.OPEN_PORT,
                    f"{host['name'] or host['ip']}:{port['port']}/{port['protocol']}",
                    self.name, host["name"] or host["ip"],
                    {"host": host["name"] or host["ip"], "ip": host["ip"], **port}))
        return findings

    @staticmethod
    def parse_sweep(output: str) -> list[str]:
        """IPs reported as up by a ``-sn`` sweep."""
        return [h["ip"] for h in _hosts(output) if h["up"] and h["ip"]]


def _hosts(xml_text: str) -> list[dict[str, Any]]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    hosts = []
    for host in root.iter("host"):
        status = host.find("status")
        ip = next((a.get("addr", "") for a in host.findall("address")
                   if a.get("addrtype") in ("ipv4", "ipv6")), "")
        hostname = next((h.get("name", "") for h in host.iter("hostname")
                         if h.get("type") == "user"), "")
        ports = []
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            svc = service.attrib if service is not None else {}
            ports.append({
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "service": svc.get("name", ""),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "extrainfo": svc.get("extrainfo", ""),
                "tunnel": svc.get("tunnel", ""),
            })
        hosts.append({
            "ip": ip, "name": hostname, "ports": ports,
            "up": status is not None and status.get("state") == "up",
        })
    return hosts
