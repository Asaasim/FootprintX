"""Scan profiles: the quick profile must cap the slow steps, even over an old config file."""

from footprintx.core.config import ModuleConfig, Settings
from footprintx.core.models import Target, TargetType
from footprintx.core.profiles import apply_profile, quick_wordlist
from footprintx.core.target_parser import TargetParser


def _settings_like_old_install() -> Settings:
    """What ~/.config/footprintx/config.yaml from an earlier install contains."""
    return Settings(modules={
        "port_scanning": ModuleConfig(top_ports=1000, max_hosts=256),
        "web_fuzzing": ModuleConfig(wordlist=None, max_targets=10, target_timeout=900),
        "subdomains": ModuleConfig(sources=["subfinder", "amass", "crtsh"]),
        "technology_detection": ModuleConfig(enabled=False),
    })


def test_quick_profile_overrides_slow_settings():
    settings = _settings_like_old_install()
    apply_profile(settings, "quick", [TargetParser().parse("example.com")])
    ports = settings.module_config("port_scanning")
    assert ports.option("top_ports") == 100 and ports.option("max_hosts") == 50
    fuzz = settings.module_config("web_fuzzing")
    assert fuzz.option("max_targets") == 3 and fuzz.option("target_timeout") == 180
    assert fuzz.option("wordlist") == str(quick_wordlist())
    assert settings.module_config("subdomains").option("sources") == ["subfinder", "crtsh"]
    assert settings.module_config("technology_detection").enabled is False  # kept
    assert settings.execution.module_timeout <= 900


def test_quick_wordlist_is_packaged_and_covers_high_risk_paths():
    words = quick_wordlist().read_text(encoding="utf-8").split()
    assert {".git", ".env", "backup.zip", "phpinfo.php", "server-status"} <= set(words)
    assert len(words) < 500


def test_quick_limits_grow_with_the_number_of_domains():
    settings = Settings()
    targets = [Target(f"site{i}.example", TargetType.DOMAIN) for i in range(4)]
    apply_profile(settings, "quick", targets)
    assert settings.module_config("port_scanning").option("max_hosts") == 200
    assert settings.module_config("web_fuzzing").option("max_targets") == 12
    # applying twice (guided mode, then scan) does not compound
    apply_profile(settings, "quick", targets)
    assert settings.module_config("port_scanning").option("max_hosts") == 200


def test_custom_wordlist_survives_quick_profile():
    settings = Settings(modules={"web_fuzzing": ModuleConfig(wordlist="/my/list.txt")})
    apply_profile(settings, "quick", [Target("example.com", TargetType.DOMAIN)])
    assert settings.module_config("web_fuzzing").option("wordlist") == "/my/list.txt"


def test_thorough_profile_keeps_the_config_file():
    settings = _settings_like_old_install()
    apply_profile(settings, "thorough", [Target("example.com", TargetType.DOMAIN)])
    assert settings.module_config("port_scanning").option("top_ports") == 1000
    assert settings.module_config("web_fuzzing").option("max_targets") == 10
