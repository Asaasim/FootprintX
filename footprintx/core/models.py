"""Shared internal data structures (spec §9.1 — normalised findings)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from footprintx.utils.helpers import utc_now


class TargetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"


ALL_TARGET_TYPES: frozenset[TargetType] = frozenset(TargetType)
HOSTNAME_TYPES: frozenset[TargetType] = frozenset({TargetType.DOMAIN, TargetType.SUBDOMAIN})
IP_TYPES: frozenset[TargetType] = frozenset({TargetType.IPV4, TargetType.IPV6, TargetType.CIDR})


@dataclass(frozen=True, slots=True)
class Target:
    """A validated, normalised scan target. Equality ignores the raw input (for dedup)."""

    value: str
    type: TargetType
    raw: str = field(default="", compare=False)

    @property
    def host(self) -> str | None:
        """Hostname or IP this target points at (``None`` for CIDR ranges)."""
        if self.type is TargetType.URL:
            return urlsplit(self.value).hostname
        if self.type is TargetType.CIDR:
            return None
        return self.value


class FindingKind(StrEnum):
    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    IP_ADDRESS = "ip_address"
    LIVE_HOST = "live_host"
    URL = "url"
    OPEN_PORT = "open_port"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    EMAIL = "email"
    INTEL = "intel"
    OBSERVATION = "observation"


_TARGET_SCOPED_KINDS = frozenset({
    FindingKind.TECHNOLOGY, FindingKind.ENDPOINT, FindingKind.OBSERVATION, FindingKind.INTEL,
})

#: Severity levels for OBSERVATION findings, most severe first.
SEVERITIES = ("high", "medium", "low", "info")


def observation(title: str, target: str, source: str, severity: str, detail: str) -> Finding:
    """A potential security observation (spec §8.1) — e.g. an exposed .git directory."""
    return Finding(FindingKind.OBSERVATION, title, source, target,
                   {"severity": severity, "detail": detail})


@dataclass(slots=True)
class Finding:
    """One normalised observation. ``source`` preserves attribution (spec §5.8, §9.2)."""

    kind: FindingKind
    value: str
    source: str
    target: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=utc_now)

    @property
    def key(self) -> tuple[FindingKind, str, str]:
        """Identity used for deduplication across tools.

        For kinds whose value is only meaningful relative to an asset (a technology,
        an endpoint, an observation, intel), the target is part of the identity.
        """
        scoped = self.kind in _TARGET_SCOPED_KINDS
        return self.kind, self.value.lower(), (self.target or "").lower() if scoped else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "source": self.source,
            "target": self.target,
            "data": self.data,
            "discovered_at": self.discovered_at.isoformat(),
        }


#: Kinds compared between scans to report newly discovered assets (spec §5.1).
TRACKED_KINDS = frozenset({
    FindingKind.SUBDOMAIN, FindingKind.LIVE_HOST, FindingKind.URL, FindingKind.OPEN_PORT,
    FindingKind.ENDPOINT, FindingKind.OBSERVATION,
})


def change_key(kind: str, value: str, target: str | None) -> str:
    """Identity of a finding when comparing scans (observations are per target)."""
    scoped = kind == FindingKind.OBSERVATION.value
    return f"{kind}|{value.lower()}|{(target or '').lower() if scoped else ''}"


@dataclass(frozen=True, slots=True)
class Baseline:
    """The previous completed scan of the same targets."""

    session_id: str
    started_at: str
    keys: frozenset[str]


class ModuleStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(slots=True)
class ModuleResult:
    """Outcome of one module run — always produced, even on failure (spec §6.3)."""

    module: str
    status: ModuleStatus = ModuleStatus.PENDING
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: Non-fatal remarks, e.g. "assetfinder not installed".
    notes: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def duration(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        """Status summary (findings are reported separately)."""
        return {
            "module": self.module,
            "status": self.status.value,
            "findings": len(self.findings),
            "errors": self.errors,
            "notes": self.notes,
            "skip_reason": self.skip_reason,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration": self.duration,
        }
