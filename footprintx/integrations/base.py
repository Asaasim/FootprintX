"""Base classes for integrations.

* :class:`ToolIntegration` — an external CLI tool executed as a subprocess.
* :class:`ApiIntegration`  — a remote intelligence/proxy API reached over HTTP.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from footprintx.core.config import get_secret
from footprintx.core.models import Finding, FindingKind
from footprintx.core.process_manager import CommandResult, run_command
from footprintx.utils.locations import is_wsl, user_home
from footprintx.utils.platform import detect_platform
from footprintx.utils.validators import hostnames_in

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.]+)?")


#: Tools that Ubuntu/Debian package too (the rest are Kali-only packages).
DEBIAN_PACKAGES = frozenset({"nmap", "ffuf", "gobuster", "whatweb"})
#: Kali-only packages that install.sh downloads itself on Ubuntu/Debian.
INSTALLER_FETCHED = frozenset({"subfinder", "httpx-toolkit", "naabu", "findomain",
                               "assetfinder", "theharvester"})


def _search_dirs() -> list[str]:
    """``PATH``, plus ``~/.local/bin`` where install.sh puts tools on Ubuntu/Debian
    (it is only added to ``PATH`` at the next login)."""
    dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]
    if is_wsl():
        # WSL adds Windows' own PATH: very slow to search, and its programs aren't ours.
        dirs = [d for d in dirs if not d.startswith("/mnt/")]
    local_bin = str(user_home() / ".local" / "bin")
    if local_bin not in dirs:
        dirs.append(local_bin)
    return dirs


class ToolNotFoundError(RuntimeError):
    pass


class Integration(ABC):  # noqa: B024 — abstract marker; subclasses add the abstract parts
    name: ClassVar[str]
    display_name: ClassVar[str]
    required: ClassVar[bool] = False
    #: Generic (non-apt) installation instructions.
    install_hint: ClassVar[str] = ""

    def installation_hint(self) -> str:
        return self.install_hint


class ToolIntegration(Integration):
    #: Executable names in preference order — distros rename some tools
    #: (Kali ships ProjectDiscovery's httpx as ``httpx-toolkit``).
    binaries: ClassVar[tuple[str, ...]]
    #: Kali/Debian package providing the tool.
    apt_package: ClassVar[str | None] = None
    #: Arguments that print the tool's version; empty if the tool has none.
    version_args: ClassVar[tuple[str, ...]] = ("-version",)
    #: If the version output contains any of these, the binary is a different program
    #: with the same name (e.g. Python's ``httpx`` script) and is skipped on PATH.
    reject_markers: ClassVar[tuple[str, ...]] = ()

    def installation_hint(self) -> str:
        info = detect_platform()
        if self.apt_package and (info.is_kali or
                                 (info.uses_apt and self.apt_package in DEBIAN_PACKAGES)):
            return f"sudo apt install {self.apt_package}"
        if info.uses_apt and self.apt_package in INSTALLER_FETCHED:
            # Ubuntu/Debian don't package it; install.sh fetches the official release.
            return "run  bash install.sh  again in the FootprintX folder"
        return self.install_hint

    def locate(self, override: str | None = None) -> str | None:
        """Resolve the executable: explicit config path first, then ``PATH``."""
        if override:
            return override if Path(override).is_file() else shutil.which(override)
        for binary in self.binaries:
            found = self._find_on_path(binary)
            if found:
                return found
        return None

    def _find_on_path(self, binary: str) -> str | None:
        for directory in _search_dirs():
            candidate = shutil.which(binary, path=directory)
            if candidate and not (self.reject_markers and any(
                    m in self._version_output(candidate) for m in self.reject_markers)):
                return candidate
        return None

    def detect_version(self, path: str) -> str | None:
        match = _VERSION.search(self._version_output(path))
        return match.group(0) if match else None

    def _version_output(self, path: str, timeout: float = 10.0) -> str:
        if not self.version_args:
            return ""
        try:
            proc = subprocess.run(
                [path, *self.version_args],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return _ANSI.sub("", f"{proc.stdout}\n{proc.stderr}")

    async def execute(
        self, args: Sequence[str], *, timeout: float | None = None, override: str | None = None
    ) -> CommandResult:
        path = self.locate(override)
        if path is None:
            raise ToolNotFoundError(f"{self.display_name} is not installed")
        return await run_command([path, *args], timeout=timeout)

    @abstractmethod
    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        """Convert raw tool output for ``target`` into findings (keep the raw output too)."""


class SubdomainToolIntegration(ToolIntegration):
    """A tool that prints discovered hostnames for a domain."""

    @abstractmethod
    def subdomain_args(self, domain: str) -> list[str]:
        """Command-line arguments for passive subdomain enumeration of ``domain``."""

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        return [
            Finding(FindingKind.SUBDOMAIN, host, self.name, target)
            for host in hostnames_in(output, target)
            if host != target
        ]


class ApiIntegration(Integration):
    base_url: ClassVar[str]
    #: Environment variable holding the credential; ``None`` if no key is needed.
    api_key_env: ClassVar[str | None] = None

    def api_key(self) -> str | None:
        return get_secret(self.api_key_env) if self.api_key_env else None

    def is_configured(self) -> bool:
        return self.api_key_env is None or self.api_key() is not None
