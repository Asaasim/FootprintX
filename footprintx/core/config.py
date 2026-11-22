"""Configuration loading (spec §11).

Resolution order: explicit ``--config`` path → ``$FOOTPRINTX_CONFIG`` →
``./config/config.yaml`` → ``~/.config/footprintx/config.yaml`` → built-in
defaults. Secrets come from environment variables / ``.env`` files only (``./.env``
and ``~/.config/footprintx/.env``), never from the YAML file.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError

CONFIG_ENV_VAR = "FOOTPRINTX_CONFIG"
DEFAULT_CONFIG_PATH = Path("config/config.yaml")
USER_CONFIG_DIR = Path.home() / ".config" / "footprintx"
USER_CONFIG_PATH = USER_CONFIG_DIR / "config.yaml"
USER_ENV_PATH = USER_CONFIG_DIR / ".env"
DEFAULT_RESULTS_DIR = Path.home() / "FootprintX-results"


class ConfigError(Exception):
    """Raised when the configuration file is missing, malformed or invalid."""


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


class OutputConfig(BaseModel):
    directory: Path = DEFAULT_RESULTS_DIR
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "txt"])


class SafetyConfig(BaseModel):
    require_authorization: bool = True
    respect_scope: bool = True
    max_requests_per_second: float = Field(default=50, gt=0)


class LoggingConfig(BaseModel):
    level: str = "INFO"


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    modules: dict[str, ModuleConfig] = Field(default_factory=dict)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    #: File the settings were loaded from (``None`` = built-in defaults).
    source: Path | None = Field(default=None, exclude=True)

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
            (p for p in (DEFAULT_CONFIG_PATH, USER_CONFIG_PATH) if p.is_file()), None)

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
    return settings


def get_secret(name: str) -> str | None:
    """Read a credential from the environment (populated from ``.env`` if present)."""
    value = os.environ.get(name, "").strip()
    return value or None
