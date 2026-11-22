"""``footprintx doctor`` checks (spec §12)."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass

from footprintx.core.config import Settings
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.base import ApiIntegration, Integration, ToolIntegration

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
        *(check_integration(i, settings) for i in INTEGRATION_REGISTRY.values()),
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
            integration.display_name, False, "Missing", integration.install_hint,
            integration.required,
        )
    version = integration.detect_version(path)
    detail = f"{version}  {path}" if version else path
    return CheckResult(integration.display_name, True, "Installed", detail, integration.required)


def check_config(settings: Settings, error: str | None) -> CheckResult:
    if error:
        return CheckResult("Configuration", False, "Invalid", error, required=True)
    return CheckResult(
        "Configuration", True, "Valid", str(settings.source or "built-in defaults"), required=True
    )
