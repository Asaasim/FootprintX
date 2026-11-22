"""Authorised-scope enforcement (spec §13.1–13.2).

Every target — supplied or discovered — must pass :meth:`ScopeManager.is_in_scope`
before any active module touches it. Exclusions always win over inclusions.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from footprintx.core.config import ScopeConfig
from footprintx.core.models import Target

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeManager:
    def __init__(
        self, include: Iterable[str], exclude: Iterable[str] = (), *, allow_all: bool = False
    ) -> None:
        self._include_domains, self._include_networks = self._split(include)
        self._exclude_domains, self._exclude_networks = self._split(exclude)
        self._allow_all = allow_all

    @classmethod
    def allow_all(cls, exclude: Iterable[str] = ()) -> ScopeManager:
        """Used only when ``safety.respect_scope`` is disabled."""
        return cls((), exclude, allow_all=True)

    @classmethod
    def from_settings(cls, scope: ScopeConfig, seeds: Iterable[Target]) -> ScopeManager:
        """Use configured scope, or fall back to the user-supplied seed targets."""
        include = scope.include or [t.host or t.value for t in seeds]
        return cls(include, scope.exclude)

    def is_in_scope(self, value: str) -> bool:
        host = self._host_of(value)
        network = self._as_network(host)
        if network is not None:
            if any(network.version == n.version and network.subnet_of(n)  # type: ignore[arg-type]
                   for n in self._exclude_networks):
                return False
            return self._allow_all or any(
                network.version == n.version and network.subnet_of(n)  # type: ignore[arg-type]
                for n in self._include_networks)

        host = host.rstrip(".").lower()
        if any(self._domain_match(host, d) for d in self._exclude_domains):
            return False
        return self._allow_all or any(self._domain_match(host, d) for d in self._include_domains)

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _domain_match(host: str, domain: str) -> bool:
        return host == domain or host.endswith("." + domain)

    @staticmethod
    def _host_of(value: str) -> str:
        if "://" in value:
            return urlsplit(value).hostname or ""
        return value.strip()

    @staticmethod
    def _as_network(value: str) -> IPNetwork | None:
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

    def _split(self, entries: Iterable[str]) -> tuple[list[str], list[IPNetwork]]:
        domains: list[str] = []
        networks: list[IPNetwork] = []
        for entry in entries:
            host = self._host_of(entry)
            network = self._as_network(host)
            if network is not None:
                networks.append(network)
            elif host:
                domains.append(host.rstrip(".").lower())
        return domains, networks
