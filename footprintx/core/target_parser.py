"""Target identification, validation and normalisation (spec §4.1)."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import tldextract

from footprintx.core.models import Target, TargetType
from footprintx.utils.validators import is_valid_hostname

# Use the bundled Public Suffix List snapshot — no network access at parse time.
_extract = tldextract.TLDExtract(suffix_list_urls=())

_DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidTargetError(ValueError):
    """The input could not be recognised as a supported target type."""


class TargetParser:
    def parse(self, raw: str) -> Target:
        value = raw.strip()
        if not value:
            raise InvalidTargetError("empty target")

        if "://" in value:
            return Target(self._normalise_url(value), TargetType.URL, raw)

        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            kind = TargetType.IPV4 if ip.version == 4 else TargetType.IPV6
            return Target(ip.compressed, kind, raw)

        if "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise InvalidTargetError(
                    "not a valid CIDR range (for URLs include the scheme, e.g. https://)"
                ) from exc
            return Target(network.compressed, TargetType.CIDR, raw)

        host = self._normalise_hostname(value)
        return Target(host, self._hostname_type(host), raw)

    def parse_many(self, raws: Iterable[str]) -> tuple[list[Target], list[tuple[str, str]]]:
        """Parse and dedupe, preserving input order. Returns ``(targets, [(raw, reason)])``."""
        targets: list[Target] = []
        seen: set[Target] = set()
        invalid: list[tuple[str, str]] = []
        for raw in raws:
            try:
                target = self.parse(raw)
            except InvalidTargetError as exc:
                invalid.append((raw, str(exc)))
                continue
            if target not in seen:
                seen.add(target)
                targets.append(target)
        return targets, invalid

    @staticmethod
    def read_file(path: Path) -> list[str]:
        """One target per line; blank lines and ``#`` comments are ignored."""
        lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
        return [line for line in lines if line and not line.startswith("#")]

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _normalise_hostname(value: str) -> str:
        host = value.strip().rstrip(".").lower()
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            host = ""
        if not is_valid_hostname(host):
            raise InvalidTargetError("not a valid domain, IP address, CIDR range or URL")
        return host

    @staticmethod
    def _hostname_type(host: str) -> TargetType:
        parts = _extract(host)
        if parts.suffix:
            return TargetType.SUBDOMAIN if parts.subdomain else TargetType.DOMAIN
        # Unknown suffix (e.g. internal TLDs): fall back to label count.
        return TargetType.SUBDOMAIN if host.count(".") >= 2 else TargetType.DOMAIN

    def _normalise_url(self, value: str) -> str:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise InvalidTargetError(f"unsupported URL scheme {parts.scheme!r} (use http/https)")
        try:
            port = parts.port
        except ValueError as exc:
            raise InvalidTargetError("invalid port in URL") from exc
        if not parts.hostname:
            raise InvalidTargetError("URL has no host")

        try:
            ip = ipaddress.ip_address(parts.hostname)
            host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
        except ValueError:
            host = self._normalise_hostname(parts.hostname)

        netloc = host if port in (None, _DEFAULT_PORTS[scheme]) else f"{host}:{port}"
        return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
