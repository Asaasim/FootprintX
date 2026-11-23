"""HTTPx wrapper (ProjectDiscovery).

Kali installs it as ``httpx-toolkit`` because ``/usr/bin/httpx`` belongs to the
Python httpx library (python3-httpx). Elsewhere the Go binary is called ``httpx``;
Python ``httpx`` scripts are recognised by their output and skipped. Set
``tools.paths.httpx`` in config.yaml to force a specific binary.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from footprintx.core.models import Finding
from footprintx.integrations.base import ToolIntegration


class HttpxIntegration(ToolIntegration):
    name = "httpx"
    display_name = "HTTPx"
    binaries = ("httpx-toolkit", "httpx")
    apt_package = "httpx-toolkit"
    version_args = ("-version",)
    # Python httpx[cli] prints a click usage line; without the extra it asks for httpx[cli].
    reject_markers = ("[OPTIONS] URL", "httpx[cli]")
    install_hint = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def probe_args(self, input_file: str, *, threads: int, rate: int, timeout: int,
                   proxy: str | None = None, resolvers: list[str] | None = None
                   ) -> list[str]:
        args = [
            "-l", input_file, "-json", "-silent", "-nc",
            "-sc", "-title", "-server", "-td", "-cl", "-location", "-ip", "-cdn",
            "-no-fallback",          # report both http:// and https:// when both answer
            "-t", str(threads), "-rl", str(rate), "-timeout", str(timeout),
        ]
        if proxy:
            args += ["-http-proxy", proxy]
        if resolvers:  # otherwise httpx uses its own public resolver list
            args += ["-r", ",".join(resolvers)]
        return args

    def parse_probes(self, output: str) -> list[dict[str, Any]]:
        """JSON lines → normalised probe records (same shape as the native prober)."""
        probes = []
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("failed"):
                continue
            url = str(row.get("url", ""))
            parts = urlsplit(url)
            if not parts.hostname:
                continue
            probes.append({
                "url": url.rstrip("/"),
                "host": parts.hostname,
                "scheme": parts.scheme,
                "port": parts.port or (443 if parts.scheme == "https" else 80),
                "status_code": row.get("status_code"),
                "title": row.get("title", ""),
                "webserver": row.get("webserver", ""),
                "content_length": row.get("content_length"),
                "location": row.get("location", ""),
                "tech": list(row.get("tech") or []),
                "ips": list(row.get("a") or []),
                "cdn": row.get("cdn_name") or ("yes" if row.get("cdn") else ""),
            })
        return probes

    def parse(self, output: str, target: str | None = None) -> list[Finding]:
        raise NotImplementedError("use parse_probes(); the http_probe module builds findings")
