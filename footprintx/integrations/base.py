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
from footprintx.core.models import Finding
from footprintx.core.process_manager import CommandResult, run_command

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION = re.compile(r"v?\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.]+)?")


class ToolNotFoundError(RuntimeError):
    pass


class Integration(ABC):  # noqa: B024 — abstract marker; subclasses add the abstract parts
    name: ClassVar[str]
    display_name: ClassVar[str]
    required: ClassVar[bool] = False
    install_hint: ClassVar[str] = ""


class ToolIntegration(Integration):
    binary: ClassVar[str]
    #: Arguments that print the tool's version; empty if the tool has none.
    version_args: ClassVar[tuple[str, ...]] = ("-version",)
    #: If the version output contains any of these, the binary is a different program
    #: with the same name (e.g. Python's ``httpx`` script) and is skipped on PATH.
    reject_markers: ClassVar[tuple[str, ...]] = ()

    def locate(self, override: str | None = None) -> str | None:
        """Resolve the executable: explicit config path first, then ``PATH``."""
        if override:
            return override if Path(override).is_file() else shutil.which(override)
        if not self.reject_markers:
            return shutil.which(self.binary)
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            candidate = shutil.which(self.binary, path=directory) if directory else None
            if candidate and not any(m in self._version_output(candidate)
                                     for m in self.reject_markers):
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
    def parse(self, output: str) -> list[Finding]:
        """Convert raw tool output into normalised findings (keep the raw output too)."""


class ApiIntegration(Integration):
    base_url: ClassVar[str]
    #: Environment variable holding the credential; ``None`` if no key is needed.
    api_key_env: ClassVar[str | None] = None

    def api_key(self) -> str | None:
        return get_secret(self.api_key_env) if self.api_key_env else None

    def is_configured(self) -> bool:
        return self.api_key_env is None or self.api_key() is not None
