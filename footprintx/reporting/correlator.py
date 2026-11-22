"""Build the asset tree: domain → subdomains → IPs → ports/tech/endpoints (spec §9.3)."""

from __future__ import annotations

from dataclasses import dataclass, field

from footprintx.core.models import Finding


@dataclass
class AssetNode:
    value: str
    kind: str
    findings: list[Finding] = field(default_factory=list)
    children: list[AssetNode] = field(default_factory=list)


def correlate(findings: list[Finding]) -> list[AssetNode]:
    raise NotImplementedError
