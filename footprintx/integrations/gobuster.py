"""Gobuster wrapper — directory brute forcing (fallback when FFUF is missing)."""

from __future__ import annotations

import re

from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ToolIntegration

_LINE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[-->\s*(?P<redirect>\S+)\])?")


class GobusterIntegration(ToolIntegration):
    name = "gobuster"
    display_name = "Gobuster"
    binaries = ("gobuster",)
    apt_package = "gobuster"
    version_args = ("--version",)
    install_hint = "go install github.com/OJ/gobuster/v3@latest"

    def fuzz_args(self, base_url: str, wordlist: str, *, threads: int, timeout: int,
                  match_status: list[int], extensions: list[str], method: str = "GET",
                  proxy: str | None = None) -> list[str]:
        args = [
            "dir", "-u", base_url, "-w", wordlist, "-q", "--no-color", "-k", "-m", method,
            "-t", str(threads), "--timeout", f"{timeout}s",
            "-s", ",".join(map(str, match_status)), "-b", "",
        ]
        if extensions:
            args += ["-x", ",".join(e.lstrip(".") for e in extensions)]
        if proxy:
            args += ["--proxy", proxy]
        return args

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        base = (target or "").rstrip("/")
        findings = []
        for line in output.splitlines():
            match = _LINE.match(line.strip())
            if not match:
                continue
            path = match["path"] if match["path"].startswith("/") else f"/{match['path']}"
            findings.append(Finding(
                FindingKind.ENDPOINT, f"{base}{path}", self.name, target,
                {"status": int(match["status"]), "length": int(match["size"]),
                 "redirect": match["redirect"] or ""}))
        return findings
