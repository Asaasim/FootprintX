"""Target identification, validation and normalisation (spec §4.1)."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import tldextract

from footprintx.core.models import Target, TargetType
from footprintx.utils.validators import is_valid_hostname

# Use the bundled Public Suffix List snapshot — no network access at parse time.
_extract = tldextract.TLDExtract(suffix_list_urls=())

_DEFAULT_PORTS = {"http": 80, "https": 443}


_COMMENT = re.compile(r"(^|\s)#.*")


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 byte-order marks
        return data.decode("utf-16")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


class InvalidTargetError(ValueError):
    """The input could not be recognised as a supported target type."""


class TargetParser:
    def parse(self, raw: str) -> Target:
        # Forgive what people commonly paste: quotes, <brackets>, "*." scope wildcards.
        value = raw.strip().strip("\"'<>").strip()
        if value.startswith("*."):
            value = value[2:]
        elif value.startswith(".") and not value.startswith(".."):
            value = value[1:]
        if not value:
            raise InvalidTargetError("empty target")
        if "@" in value and "://" not in value:
            raise InvalidTargetError("that looks like an email address — type just the part "
                                     "after the @, e.g. example.com")

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
            host, _, path = value.partition("/")
            if not _looks_like_ip(host):
                # "example.com/" or "example.com/login" without http(s)://
                if path.strip("/"):
                    return Target(self._normalise_url(f"https://{value}"), TargetType.URL, raw)
                value = host
            else:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError as exc:
                    raise InvalidTargetError("not a valid IP range (e.g. 192.168.1.0/24)"
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
        """Targets from a text file: one or more per line (separated by spaces, commas or
        semicolons); blank lines and ``#`` comments are ignored. Files saved on Windows
        (byte-order mark, UTF-16 "Unicode", CRLF line endings) work too."""
        targets: list[str] = []
        for line in _read_text(path).splitlines():
            # "#" starts a comment at the line start or after a space (not a URL's #fragment)
            line = _COMMENT.sub("", line)
            targets += [v for v in re.split(r"[\s,;]+", line) if v]
        return targets

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
