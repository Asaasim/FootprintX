"""``footprintx doctor`` checks (spec §12)."""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass

from footprintx.core.config import Settings
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.base import ApiIntegration, Integration, ToolIntegration
from footprintx.utils.platform import detect_platform, has_raw_socket_capability
from footprintx.utils.wordlists import resolve_wordlist

MIN_PYTHON = (3, 11)


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    status: str
    detail: str = ""
    required: bool = False


def run_doctor(settings: Settings, config_error: str | None = None) -> list[CheckResult]:
    return [
        check_python(),
        check_os(),
        check_privileges(settings),
        *(check_integration(i, settings) for i in INTEGRATION_REGISTRY.values()),
        check_wordlist(settings),
        check_config(settings, config_error),
    ]


def check_python() -> CheckResult:
    ok = sys.version_info >= MIN_PYTHON
    return CheckResult(
        "Python Environment",
        ok,
        "Available" if ok else "Unsupported",
        f"Python {platform.python_version()}"
        + ("" if ok else f" (need {'.'.join(map(str, MIN_PYTHON))}+)"),
        required=True,
    )


def check_os() -> CheckResult:
    info = detect_platform()
    if info.is_kali:
        return CheckResult("Operating System", True, "Kali Linux", info.os_name)
    return CheckResult(
        "Operating System", True, "Supported", f"{info.os_name} (Kali Linux is the primary target)"
    )


def check_privileges(settings: Settings | None = None) -> CheckResult:
    info = detect_platform()
    if not hasattr(os, "geteuid"):
        return CheckResult("Raw Socket Scans", True, "N/A", "not a POSIX system")
    if info.can_raw_scan:
        detail = "running as root" if info.is_root else "raw sockets via CAP_NET_RAW"
        return CheckResult("Raw Socket Scans", True, "Available", detail)
    paths = (settings or Settings()).tools.paths
    for name in ("nmap", "naabu"):
        tool = INTEGRATION_REGISTRY.get(name)
        if isinstance(tool, ToolIntegration):
            path = tool.locate(paths.get(name))
            if has_raw_socket_capability(path):
                return CheckResult("Raw Socket Scans", True, "Available",
                                   f"{tool.display_name} has raw-socket capability (no sudo "
                                   "needed)")
    return CheckResult(
        "Raw Socket Scans", False, "Unprivileged",
        "SYN scans need root (run with sudo); slower TCP connect scans will be used",
    )


def check_integration(integration: Integration, settings: Settings) -> CheckResult:
    if isinstance(integration, ApiIntegration):
        if integration.is_configured():
            return CheckResult(integration.display_name, True, "Configured")
        return CheckResult(
            integration.display_name,
            False,
            "Not Configured",
            f"set {integration.api_key_env} in .env",
            integration.required,
        )

    assert isinstance(integration, ToolIntegration)
    path = integration.locate(settings.tools.paths.get(integration.name))
    if path is None:
        return CheckResult(
            integration.display_name, False, "Missing", integration.installation_hint(),
            integration.required,
        )
    version = integration.detect_version(path)
    detail = f"{version}  {path}" if version else path
    return CheckResult(integration.display_name, True, "Installed", detail, integration.required)


def check_wordlist(settings: Settings) -> CheckResult:
    configured = settings.module_config("web_fuzzing").option("wordlist")
    path = resolve_wordlist(configured)
    if path is not None:
        return CheckResult("Fuzzing Wordlist", True, "Found", str(path))
    hint = (
        f"configured wordlist not found: {configured}"
        if configured
        else "sudo apt install seclists  (or scripts/fetch_wordlists.sh)"
    )
    return CheckResult("Fuzzing Wordlist", False, "Missing", hint)


def check_config(settings: Settings, error: str | None) -> CheckResult:
    if error:
        return CheckResult("Configuration", False, "Invalid", error, required=True)
    return CheckResult(
        "Configuration", True, "Valid", str(settings.source or "built-in defaults"), required=True
    )
