"""Asset correlation (spec §9.3): seed target → hosts → IPs, ports, sites, tech, findings."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from footprintx.core.models import SEVERITIES, Finding, FindingKind, Target, TargetType


def _host(value: str | None) -> str:
    if not value:
        return ""
    if "://" in value:
        return (urlsplit(value).hostname or "").lower()
    if ":" in value and value.count(":") == 1:  # host:port/proto
        return value.split(":", 1)[0].lower()
    return value.lower()


class _Node:
    def __init__(self, host: str) -> None:
        self.host = host
        self.ips: set[str] = set()
        self.urls: dict[str, dict[str, Any]] = {}
        self.ports: dict[tuple[int, str], dict[str, Any]] = {}
        self.technologies: dict[str, str] = {}
        self.endpoints: list[str] = []
        self.observations: list[dict[str, str]] = []
        self.reachable = False

    @property
    def has_details(self) -> bool:
        return bool(self.reachable or self.ips or self.urls or self.ports or self.technologies
                    or self.endpoints or self.observations)

    def to_dict(self) -> dict[str, Any]:
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        return {
            "host": self.host,
            "ips": sorted(self.ips),
            "urls": list(self.urls.values()),
            "ports": [self.ports[k] for k in sorted(self.ports)],
            "technologies": [f"{n} {v}".strip() for n, v in sorted(self.technologies.items())],
            "endpoints": sorted(set(self.endpoints)),
            "observations": sorted(self.observations,
                                   key=lambda o: rank.get(o["severity"], len(rank))),
        }


def correlate(targets: list[Target], findings: list[Finding]) -> list[dict[str, Any]]:
    nodes: dict[str, _Node] = {}

    def node(host: str) -> _Node:
        return nodes.setdefault(host, _Node(host))

    ip_owners: dict[str, set[str]] = {}
    for f in findings:
        if f.kind is FindingKind.IP_ADDRESS:
            hostnames = f.data.get("hostnames") or []
            for h in hostnames:
                node(h.lower()).ips.add(f.value)
                ip_owners.setdefault(f.value, set()).add(h.lower())
            if not hostnames or f.data.get("seed") or f.data.get("from_range"):
                ip_node = node(f.value)
                if f.data.get("seed") or f.data.get("reachable"):
                    ip_node.reachable = True

    for f in findings:
        if f.kind in (FindingKind.SUBDOMAIN, FindingKind.LIVE_HOST):
            node(f.value.lower())
        elif f.kind is FindingKind.URL and f.data.get("live"):
            node(_host(f.value)).urls[f.value] = {
                "url": f.value, "status": f.data.get("status_code"),
                "title": f.data.get("title", ""), "server": f.data.get("webserver", "")}
        elif f.kind is FindingKind.OPEN_PORT:
            host = _host(str(f.data.get("host") or f.target or f.value))
            port = {"port": f.data.get("port"), "protocol": f.data.get("protocol", "tcp"),
                    "service": " ".join(str(f.data.get(k) or "") for k in
                                        ("service", "product", "version")).strip(),
                    "sources": f.data.get("sources", [f.source])}
            # ports found on an IP belong to every hostname that resolves to it
            owners = ip_owners.get(host) or {host}
            for owner in owners:
                node(owner).ports.setdefault((int(port["port"] or 0), port["protocol"]), port)
        elif f.kind is FindingKind.TECHNOLOGY:
            host = _host(str(f.data.get("host") or f.target))
            if host:
                tech = node(host).technologies
                version = str(f.data.get("version") or "")
                if f.value not in tech or (version and not tech[f.value]):
                    tech[f.value] = version
        elif f.kind is FindingKind.ENDPOINT:
            node(_host(f.value)).endpoints.append(f.value)
        elif f.kind is FindingKind.OBSERVATION:
            host = _host(f.target)
            owners = ip_owners.get(host) or {host}
            for owner in owners:
                node(owner).observations.append({
                    "title": f.value, "severity": f.data.get("severity", "info"),
                    "detail": f.data.get("detail", ""), "target": f.target or ""})

    nodes.pop("", None)
    tree: list[dict[str, Any]] = []
    placed: set[str] = set()
    for target in targets:
        members = sorted(h for h in nodes if _belongs(h, target))
        placed.update(members)
        # Names with nothing else known (e.g. CT-log subdomains that don't resolve)
        # are counted, not listed — a big target can have tens of thousands.
        detailed = [h for h in members if nodes[h].has_details]
        tree.append({"root": target.value, "type": target.type.value,
                     "hosts": [nodes[h].to_dict() for h in detailed],
                     "other_names": len(members) - len(detailed)})
    others = sorted(h for h in nodes
                    if h not in placed and (nodes[h].ports or nodes[h].urls))
    if others:
        tree.append({"root": "other related assets", "type": "other",
                     "hosts": [nodes[h].to_dict() for h in others], "other_names": 0})
    return tree


def count_hosts(tree: list[dict[str, Any]]) -> int:
    """Distinct hosts something is known about (resolves, answers, has ports …)."""
    return len({h["host"] for group in tree for h in group["hosts"]})


def _belongs(host: str, target: Target) -> bool:
    if target.type in (TargetType.DOMAIN, TargetType.SUBDOMAIN):
        return host == target.value or host.endswith("." + target.value)
    if target.type is TargetType.URL:
        return host == (target.host or "")
    if target.type in (TargetType.IPV4, TargetType.IPV6):
        return host == target.value
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(target.value)
    except ValueError:
        return False
