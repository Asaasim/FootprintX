"""Scan profiles: how deep a scan goes, and therefore how long it takes.

* ``quick`` (default) — the findings that matter most in minutes rather than an
  hour: top 100 ports plus the risky services, a short high-value wordlist on the
  main websites, and tighter caps and timeouts everywhere.
* ``thorough`` — the configuration file as written (top 1000 ports, the full
  wordlist on up to 10 websites, …). Typically 30–60+ minutes per domain.

Quick-profile limits override the configuration file, so they also apply to
config files created by older installs. Size limits grow with the number of
targets, so a list of domains isn't squeezed into the limits for one.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

from footprintx.core.config import ModuleConfig, Settings
from footprintx.core.models import Target, TargetType

PROFILES = ("quick", "thorough")
DEFAULT_PROFILE = "quick"

#: Per-module option overrides for the quick profile. Values marked as size
#: limits are multiplied by the number of domain targets (see SCALED).
QUICK_OPTIONS: dict[str, dict[str, Any]] = {
    "subdomains": {"source_timeout": 180},
    "osint": {"harvester_timeout": 180},
    "dns": {"max_hosts": 2000},
    "port_scanning": {"top_ports": 100, "max_hosts": 50, "host_timeout": "5m"},
    "technology_detection": {"max_urls": 25},
    "web_fuzzing": {"max_targets": 3, "target_timeout": 180},
}
SCALED = {("dns", "max_hosts"), ("port_scanning", "max_hosts"),
          ("technology_detection", "max_urls"), ("web_fuzzing", "max_targets")}
#: Scaling stops here so a long target list stays manageable.
MAX_SCALE = 10
#: Hard cap per module in the quick profile (seconds).
QUICK_MODULE_TIMEOUT = 900.0
#: Slow sources left out of the quick profile.
QUICK_SKIP_SOURCES = {"amass"}


def quick_wordlist() -> Path:
    """The short, high-value fuzzing wordlist shipped with FootprintX."""
    return Path(str(resources.files("footprintx.data") / "quick_wordlist.txt"))


def apply_profile(settings: Settings, profile: str, targets: list[Target]) -> None:
    """Adjust ``settings`` in place for ``profile``."""
    if profile not in PROFILES:
        raise ValueError(f"unknown scan profile {profile!r}; choose from {', '.join(PROFILES)}")
    if profile == "thorough":
        return

    domains = sum(1 for t in targets if t.type in (TargetType.DOMAIN, TargetType.SUBDOMAIN,
                                                   TargetType.URL))
    scale = min(max(domains, 1), MAX_SCALE)
    for module, overrides in QUICK_OPTIONS.items():
        current = settings.module_config(module)
        options = {**current.model_dump()}
        for key, value in overrides.items():
            options[key] = value * scale if (module, key) in SCALED else value
        if module == "web_fuzzing" and not current.option("wordlist"):
            options["wordlist"] = str(quick_wordlist())
        if module == "subdomains" and current.option("sources"):
            options["sources"] = [s for s in current.option("sources")
                                  if s not in QUICK_SKIP_SOURCES]
        settings.modules[module] = ModuleConfig(**options)
    settings.execution.module_timeout = min(settings.execution.module_timeout,
                                            QUICK_MODULE_TIMEOUT)
