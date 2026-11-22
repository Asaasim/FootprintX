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
    def key(self) -> tuple[FindingKind, str]:
        """Identity used for deduplication across tools."""
        return self.kind, self.value.lower()


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
    skip_reason: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def duration(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
