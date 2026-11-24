"""Port and service scanning (spec §5.5).

Scans resolved in-scope hostnames and in-scope IPs. Nmap is preferred because it
also identifies services and versions; Naabu is the fallback. SYN scans are used
when raw sockets are available (root, or the Docker image), TCP connect otherwise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from footprintx.core.models import (
    HOSTNAME_TYPES,
    IP_TYPES,
    Finding,
    ModuleResult,
    ModuleStatus,
    observation,
)
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.naabu import NaabuIntegration
from footprintx.integrations.nmap import NmapIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.common import (
    dns_resolvers,
    locate,
    missing_tool_note,
    most_relevant_first,
    resolved_hostnames,
    run_tool,
    scan_ips,
    skipped,
)
from footprintx.utils.platform import detect_platform, has_raw_socket_capability

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

#: Services that should rarely be reachable from the internet.
RISKY_SERVICES = {
    21: ("FTP", "medium"), 23: ("Telnet", "high"), 445: ("SMB", "high"),
    1433: ("Microsoft SQL Server", "high"), 1521: ("Oracle database", "high"),
    2375: ("Docker API (unencrypted)", "high"), 3306: ("MySQL", "high"),
    3389: ("Remote Desktop (RDP)", "medium"), 5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"), 6379: ("Redis", "high"), 9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"), 27017: ("MongoDB", "high"),
}


class PortScanningModule(BaseModule):
    name = "port_scanning"
    description = "Find open ports and identify the services and versions behind them."
    applies_to = HOSTNAME_TYPES | IP_TYPES
    depends_on = ("ip_discovery",)
    integrations = ("nmap", "naabu")
    options = frozenset({"extra_ports", "host_timeout", "max_hosts", "rate", "scanner",
                         "top_ports"})
    active = True

    async def run(self, context: ScanContext) -> ModuleResult:
        targets = most_relevant_first(context, [*resolved_hostnames(context), *scan_ips(context)])
        max_hosts = int(self.config.option("max_hosts", 256))
        if not targets:
            return skipped(self.name, "no resolved hosts or in-scope IPs to scan")

        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        if len(targets) > max_hosts:
            result.notes.append(f"{len(targets)} hosts found; scanning the first {max_hosts} "
                                "(raise modules.port_scanning.max_hosts to scan more)")
            targets = targets[:max_hosts]

        top_ports = int(self.config.option("top_ports", 1000))
        targets_file = str(context.save_raw("port_scan_targets.txt", "\n".join(targets) + "\n"))
        scanner = str(self.config.option("scanner", "auto"))
        nmap = INTEGRATION_REGISTRY["nmap"]
        naabu = INTEGRATION_REGISTRY["naabu"]
        assert isinstance(nmap, NmapIntegration) and isinstance(naabu, NaabuIntegration)
        nmap_path = locate(context, nmap) if scanner in ("auto", "nmap") else None
        naabu_path = locate(context, naabu) if scanner in ("auto", "naabu") else None
        timeout = context.settings.execution.module_timeout
        scanner_path = nmap_path or naabu_path
        raw_sockets = detect_platform().can_raw_scan or has_raw_socket_capability(scanner_path)

        # Top N ports by frequency PLUS every risky-service port: several of the most
        # dangerous services (Redis, MongoDB, Elasticsearch) are outside nmap's top 1000.
        common = nmap.top_tcp_ports(top_ports)
        ports = None
        if common is not None:
            extra = [int(p) for p in self.config.option("extra_ports", [])]
            ports = sorted({*common, *RISKY_SERVICES, *extra})

        if nmap_path:
            xml_path = context.raw_dir / "nmap.xml"
            cmd = await run_tool(
                context, nmap, nmap_path,
                nmap.port_scan_args(targets_file, str(xml_path), top_ports=top_ports,
                                    raw_sockets=raw_sockets, ports=ports,
                                    host_timeout=str(self.config.option("host_timeout", "15m"))),
                "nmap_stdout.txt", timeout=timeout)
            xml = xml_path.read_text(encoding="utf-8") if xml_path.is_file() else ""
            findings = nmap.parse(xml)
            if cmd.timed_out:
                result.errors.append("nmap timed out; results may be partial")
            elif not cmd.ok and not findings:
                last = (cmd.stderr.strip().splitlines() or ["no output"])[-1]
                result.errors.append(f"nmap failed (exit {cmd.returncode}): {last[:200]}")
                result.status = ModuleStatus.FAILED
        elif naabu_path:
            result.notes.append(missing_tool_note(nmap) + " — used Naabu (no service versions)")
            rate = int(self.config.option("rate", 1000))
            cmd = await run_tool(
                context, naabu, naabu_path,
                naabu.port_scan_args(targets_file, top_ports=top_ports, rate=rate,
                                     raw_sockets=raw_sockets, ports=ports,
                                     resolvers=dns_resolvers(context)),
                "naabu.jsonl", timeout=timeout)
            findings = naabu.parse(cmd.stdout)
            if not cmd.ok and not findings:
                result.errors.append(f"naabu failed (exit {cmd.returncode})")
                result.status = ModuleStatus.FAILED
        else:
            return skipped(self.name, f"{missing_tool_note(nmap)}; {missing_tool_note(naabu)}")

        if not raw_sockets:
            result.notes.append("TCP connect scan used (run with sudo for faster SYN scans)")
        result.findings = [f for f in findings if context.scope.is_in_scope(f.data["host"])]
        result.findings += self._observations(result.findings)
        return result

    def _observations(self, ports: list[Finding]) -> list[Finding]:
        found = []
        for f in ports:
            risky = RISKY_SERVICES.get(int(f.data.get("port", 0)))
            if risky:
                service, severity = risky
                found.append(observation(
                    f"{service} exposed", f.value, self.name, severity,
                    f"{service} is reachable on {f.data['host']} port {f.data['port']}. "
                    "Such services should normally not be exposed to the internet."))
        return found
