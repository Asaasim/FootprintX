"""FFUF wrapper — web content discovery (JSON output file)."""

from __future__ import annotations

import json

from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ToolIntegration


class FfufIntegration(ToolIntegration):
    name = "ffuf"
    display_name = "FFUF"
    binaries = ("ffuf",)
    apt_package = "ffuf"
    version_args = ("-V",)
    install_hint = "go install github.com/ffuf/ffuf/v2@latest"

    def fuzz_args(self, base_url: str, wordlist: str, json_out: str, *, threads: int,
                  rate: int, timeout: int, match_status: list[int], extensions: list[str],
                  proxy: str | None = None) -> list[str]:
        args = [
            "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist,
            "-of", "json", "-o", json_out, "-s", "-noninteractive",
            "-ac",                                   # auto-calibrate away soft-404s
            "-t", str(threads), "-rate", str(rate), "-timeout", str(timeout),
            "-mc", ",".join(map(str, match_status)),
        ]
        if extensions:
            args += ["-e", ",".join(e if e.startswith(".") else f".{e}" for e in extensions)]
        if proxy:
            args += ["-x", proxy]
        return args

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        try:
            data = json.loads(output) if output.strip() else {}
        except ValueError:
            return []
        findings = []
        for row in data.get("results", []) if isinstance(data, dict) else []:
            url = str(row.get("url", ""))
            if not url:
                continue
            findings.append(Finding(
                FindingKind.ENDPOINT, url, self.name, target,
                {"status": row.get("status"), "length": row.get("length"),
                 "words": row.get("words"), "redirect": row.get("redirectlocation", ""),
                 "content_type": row.get("content-type", "")}))
        return findings
