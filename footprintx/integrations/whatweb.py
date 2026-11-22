"""WhatWeb wrapper — web technology fingerprinting (JSON log output)."""

from __future__ import annotations

import json
from typing import Any

from footprintx.core.models import Finding, FindingKind
from footprintx.integrations.base import ToolIntegration

#: WhatWeb "plugins" that describe the response rather than a technology.
IGNORED_PLUGINS = {
    "Country", "IP", "Title", "RedirectLocation", "UncommonHeaders", "Cookies", "HttpOnly",
    "X-Frame-Options", "Strict-Transport-Security", "X-XSS-Protection", "Frame",
    "PasswordField", "X-UA-Compatible", "HTML5", "Open-Graph-Protocol", "Allow",
    "Content-Language", "Meta-Author", "Meta-Refresh-Redirect", "Script", "Email",
    "Via-Proxy", "Access-Control-Allow-Methods", "HTTPServer", "MetaGenerator",
    "Content-Security-Policy", "X-Content-Type-Options", "Object", "Google-Analytics",
}


class WhatWebIntegration(ToolIntegration):
    name = "whatweb"
    display_name = "WhatWeb"
    binaries = ("whatweb",)
    apt_package = "whatweb"
    version_args = ("--version",)
    install_hint = "apt install whatweb"

    def scan_args(self, input_file: str, json_out: str, *, threads: int = 10,
                  proxy: str | None = None) -> list[str]:
        # --follow-redirect=never: a redirect could lead outside the authorised scope.
        args = ["--input-file", input_file, f"--log-json={json_out}", "--color=never",
                "--no-errors", "-a", "1", "-t", str(threads), "--quiet",
                "--follow-redirect=never"]
        if proxy:
            args.append(f"--proxy={proxy.split('://', 1)[-1].rstrip('/')}")  # host:port
        return args

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for entry in _entries(output):
            url = str(entry.get("target", "")).rstrip("/")
            for plugin, info in (entry.get("plugins") or {}).items():
                if plugin in IGNORED_PLUGINS or not isinstance(info, dict):
                    continue
                versions = info.get("version") or []
                findings.append(Finding(
                    FindingKind.TECHNOLOGY, plugin, self.name, url,
                    {"version": str(versions[0]) if versions else "",
                     "detail": ", ".join(map(str, info.get("string") or []))[:200]}))
        return findings


def _entries(output: str) -> list[dict[str, Any]]:
    """WhatWeb writes a JSON array, or one object per line, depending on version."""
    text = output.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        data = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    data.append(json.loads(line))
                except ValueError:
                    continue
    if isinstance(data, dict):
        data = [data]
    return [d for d in data if isinstance(d, dict)]
