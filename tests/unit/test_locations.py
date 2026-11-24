"""Paths shown to the user must exist on THEIR computer (sudo, Docker, WSL)."""

import sys
import types
from pathlib import Path

from footprintx.utils import locations


def _clear_caches():
    locations.in_docker.cache_clear()
    locations.is_wsl.cache_clear()


def test_user_home_under_sudo_is_the_real_user(monkeypatch):
    fake_pwd = types.SimpleNamespace(getpwnam=lambda name: types.SimpleNamespace(
        pw_dir=f"/home/{name}"))
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)
    monkeypatch.setattr(locations.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_USER", "kali")
    assert locations.user_home() == Path("/home/kali")
    monkeypatch.delenv("SUDO_USER")
    assert locations.user_home() == Path.home()


def test_docker_paths_are_translated_to_the_host(monkeypatch):
    _clear_caches()
    monkeypatch.setenv("FOOTPRINTX_IN_DOCKER", "1")
    scan = Path("/app/results/example.com/scan_1")
    monkeypatch.setenv("FOOTPRINTX_HOST_DIR", "/home/kali/FootprintX")
    assert locations.describe(scan) == "/home/kali/FootprintX/results/example.com/scan_1"
    monkeypatch.setenv("FOOTPRINTX_HOST_DIR", r"C:\Users\me\FootprintX")
    assert locations.describe(scan) == r"C:\Users\me\FootprintX\results\example.com\scan_1"
    monkeypatch.delenv("FOOTPRINTX_HOST_DIR")
    assert locations.describe(scan).startswith("results/example.com/scan_1")
    assert locations.can_open_page() is False  # no browser inside a container
    _clear_caches()


def test_wsl_shows_the_windows_path(monkeypatch):
    _clear_caches()
    monkeypatch.delenv("FOOTPRINTX_IN_DOCKER", raising=False)
    monkeypatch.setattr(locations, "in_docker", lambda: False)
    monkeypatch.setattr(locations, "windows_path",
                        lambda p: r"\\wsl.localhost\kali-linux\home\kali\r")
    path = Path("/home/kali/r")
    described = locations.describe(path)
    assert str(path) in described and r"\\wsl.localhost" in described


def test_tilde_in_output_directory_means_the_real_home(monkeypatch):
    from footprintx.core import config

    monkeypatch.setattr(config, "user_home", lambda: Path("/home/kali"))
    settings = config.Settings.model_validate({"output": {"directory": "~/FootprintX-results"}})
    assert settings.output.directory == Path("/home/kali/FootprintX-results")
