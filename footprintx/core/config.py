"""Configuration loading (spec §11).

Resolution order: explicit ``--config`` path → ``$FOOTPRINTX_CONFIG`` →
``~/.config/footprintx/config.yaml`` (created by install.sh) →
``./config/config.yaml`` (project checkout / Docker image) → built-in defaults.
The personal file wins so results always land in the same place, whichever
folder ``footprintx`` is started from.

Secrets come from environment variables / ``.env`` files only (``./.env`` and
``~/.config/footprintx/.env``), never from the YAML file.
"""

from __future__ import annotations

import difflib
import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

CONFIG_ENV_VAR = "FOOTPRINTX_CONFIG"
DEFAULT_CONFIG_PATH = Path("config/config.yaml")
USER_CONFIG_DIR = Path.home() / ".config" / "footprintx"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
USER_ENV_PATH = USER_CONFIG_DIR / ".env"
DEFAULT_RESULTS_DIR = Path.home() / "FootprintX-results"


class ConfigError(Exception):
    """Raised when the configuration file is missing, malformed or invalid."""


class ProjectConfig(BaseModel):
    name: str = "FootprintX"


class ExecutionConfig(BaseModel):
    automatic: bool = True
    concurrency: int = Field(default=10, ge=1)
    timeout: float = Field(default=15, gt=0)
    module_timeout: float = Field(default=1800, gt=0)
    retries: int = Field(default=2, ge=0)
    continue_on_error: bool = True


class ScopeConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class ModuleConfig(BaseModel):
    """Per-module settings. Unknown keys are kept for the module to read."""

    model_config = ConfigDict(extra="allow")

    enabled: bool = True

    def option(self, key: str, default: Any = None) -> Any:
        return (self.model_extra or {}).get(key, default)


class ToolsConfig(BaseModel):
    paths: dict[str, str] = Field(default_factory=dict)


#: Report formats ``output.formats`` accepts (see footprintx.reporting.pipeline).
REPORT_FORMATS = ("json", "html", "txt", "csv", "xml")


class OutputConfig(BaseModel):
    directory: Path = DEFAULT_RESULTS_DIR
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "txt", "csv"])

    @field_validator("formats")
    @classmethod
    def _known_formats(cls, value: list[str]) -> list[str]:
        formats = [f.strip().lower() for f in value]
        unknown = [f for f in formats if f not in REPORT_FORMATS]
        if unknown:
            raise ValueError(f"unknown report format(s) {', '.join(unknown)}; "
                             f"choose from {', '.join(REPORT_FORMATS)}")
        return formats


class SafetyConfig(BaseModel):
    #: No longer used — scans don't ask for confirmation. Kept so existing config
    #: files that still contain it load without a warning.
    require_authorization: bool = False
    respect_scope: bool = True
    max_requests_per_second: float = Field(default=50, gt=0)
    #: Actively scan hostnames that resolve to private/internal addresses (internal
    #: tests). Loopback and link-local addresses are never scanned via a hostname.
    allow_internal_targets: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    modules: dict[str, ModuleConfig] = Field(default_factory=dict)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    #: File the settings were loaded from (``None`` = built-in defaults).
    source: Path | None = Field(default=None, exclude=True)
    #: Problems that don't stop a scan, e.g. misspelt keys that are ignored.
    warnings: list[str] = Field(default_factory=list, exclude=True)

    def module_config(self, name: str, enabled_by_default: bool = True) -> ModuleConfig:
        return self.modules.get(name) or ModuleConfig(enabled=enabled_by_default)


def load_settings(path: Path | str | None = None) -> Settings:
    load_dotenv(Path.cwd() / ".env", override=False)  # project / current directory
    load_dotenv(USER_ENV_PATH, override=False)        # ~/.config/footprintx/.env

    explicit = path or os.environ.get(CONFIG_ENV_VAR)
    config_path: Path | None
    if explicit:
        config_path = Path(explicit)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
    else:
        config_path = next(
            (p for p in (USER_CONFIG_PATH, DEFAULT_CONFIG_PATH) if p.is_file()), None)

    data: Any = {}
    if config_path is not None:
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path}: invalid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{config_path}: top level must be a mapping")

    try:
        settings = Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{config_path}: {exc}") from exc
    settings.source = config_path
    settings.warnings = unknown_keys(data)
    return settings


def did_you_mean(key: str, valid: list[str]) -> str:
    match = difflib.get_close_matches(key, valid, n=1, cutoff=0.6)
    return f" (did you mean {match[0]!r}?)" if match else ""


def unknown_keys(data: dict[str, Any]) -> list[str]:
    """Keys in the config file that FootprintX does not know and silently ignores.

    ``modules.<name>`` entries are checked separately against the module registry
    (see :func:`footprintx.modules.module_config_warnings`).
    """
    sections = {name: info.annotation for name, info in Settings.model_fields.items()
                if name not in ("source", "warnings")}
    found: list[str] = []
    for key, value in data.items():
        if key not in sections:
            found.append(f"unknown section {key!r}{did_you_mean(str(key), list(sections))}"
                         " is ignored")
            continue
        model = sections[key]
        if not (isinstance(value, dict) and isinstance(model, type)
                and issubclass(model, BaseModel)):
            continue
        fields = list(model.model_fields)
        for sub in value:
            if sub not in fields:
                found.append(f"unknown setting '{key}.{sub}'{did_you_mean(str(sub), fields)}"
                             " is ignored")
    return found


def get_secret(name: str) -> str | None:
    """Read a credential from the environment (populated from ``.env`` if present)."""
    value = os.environ.get(name, "").strip()
    return value or None
