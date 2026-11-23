"""Host platform detection — FootprintX targets Kali Linux first."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

OS_RELEASE = Path("/etc/os-release")


@dataclass(frozen=True, slots=True)
class PlatformInfo:
    os_id: str
    os_name: str
    id_like: tuple[str, ...]
    is_root: bool

    @property
    def is_kali(self) -> bool:
        return self.os_id == "kali"

    @property
    def uses_apt(self) -> bool:
        return self.os_id in {"kali", "debian", "ubuntu"} or "debian" in self.id_like

    @property
    def can_raw_scan(self) -> bool:
        """SYN scans need root, or nmap/naabu with CAP_NET_RAW (as in the Docker image)."""
        return self.is_root or "NMAP_PRIVILEGED" in os.environ


#: Where distributions keep the real binary when the command is a wrapper script.
_REAL_BINARIES = {"nmap": ("/usr/lib/nmap/nmap",)}


def has_raw_socket_capability(path: str | None) -> bool:
    """True if ``path`` (or the binary its wrapper runs) carries file capabilities.

    Kali installs nmap with cap_net_raw so ordinary users can run SYN scans
    without sudo; naabu gets the same treatment in the Docker image.
    """
    if not path or not hasattr(os, "getxattr"):
        return False
    candidates = [os.path.realpath(path), *_REAL_BINARIES.get(Path(path).name, ())]
    for candidate in candidates:
        try:
            if os.getxattr(candidate, "security.capability"):
                return True
        except OSError:
            continue
    return False


RESOLV_CONF = Path("/etc/resolv.conf")


def system_resolvers(resolv_conf: Path = RESOLV_CONF) -> list[str]:
    """Nameservers the operating system uses (empty if unknown, e.g. on Windows).

    ProjectDiscovery tools (httpx-toolkit, naabu) otherwise resolve names through
    their own built-in list of *public* resolvers, which can't see internal or
    split-horizon DNS and silently drops hosts when those resolvers are unreachable.
    """
    try:
        text = resolv_conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    servers = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
    return servers


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.startswith("#"):
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


@lru_cache(maxsize=1)
def detect_platform() -> PlatformInfo:
    release: dict[str, str] = {}
    if OS_RELEASE.is_file():
        release = parse_os_release(OS_RELEASE.read_text(encoding="utf-8", errors="replace"))
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    return PlatformInfo(
        os_id=release.get("ID", sys.platform).lower(),
        os_name=release.get("PRETTY_NAME", sys.platform),
        id_like=tuple(release.get("ID_LIKE", "").lower().split()),
        is_root=is_root,
    )
