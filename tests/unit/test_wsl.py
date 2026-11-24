"""FootprintX inside WSL: Windows results folder, shortcuts, staying awake."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from footprintx.utils import locations, wsl


def _scan(root: Path, name: str = "scan_20261124_101500") -> Path:
    scan = root / "example.com" / name
    (scan / "reports").mkdir(parents=True)
    (scan / "raw").mkdir()
    (scan / "reports" / "report.txt").write_text("report")
    (scan / "subdomains.txt").write_text("a.example.com")
    (scan / "raw" / "nmap.xml").write_text("<x/>")
    (scan / "scan.log").write_text("log")
    return scan


@pytest.fixture
def windows_results(tmp_path, monkeypatch):
    folder = tmp_path / "windows" / "FootprintX-results"
    monkeypatch.setattr(wsl, "results_dir", lambda: folder)
    return folder


def test_reports_are_copied_to_the_windows_folder(tmp_path, windows_results):
    scan = _scan(tmp_path / "linux")
    copy = wsl.copy_scan(scan)
    assert copy == windows_results / "example.com" / scan.name
    assert (copy / "reports" / "report.txt").read_text() == "report"
    assert (copy / "subdomains.txt").is_file()
    assert not (copy / "raw").exists() and not (copy / "scan.log").exists()
    assert wsl.copied(scan / "reports" / "report.txt") == copy / "reports" / "report.txt"


def test_not_copied_outside_wsl_or_when_already_on_a_windows_drive(tmp_path, monkeypatch,
                                                                   windows_results):
    assert wsl.copy_location(Path("/mnt/c/x/example.com/scan_20261124_101500")) is None \
        or not Path("/mnt/c").is_absolute()  # "/mnt" paths aren't absolute on Windows
    assert wsl.copy_location(tmp_path / "somewhere") is None  # not a scan folder
    monkeypatch.setattr(wsl, "results_dir", lambda: None)
    assert wsl.copy_scan(_scan(tmp_path / "linux")) is None


def test_a_failing_copy_never_breaks_the_scan(tmp_path, monkeypatch, windows_results):
    scan = _scan(tmp_path / "linux")

    def locked(*_args):
        raise PermissionError("open in Excel")

    monkeypatch.setattr(wsl.shutil, "copyfile", locked)
    assert wsl.copy_scan(scan) is None


def test_paths_are_shown_as_windows_paths(tmp_path, monkeypatch, windows_results):
    scan = _scan(tmp_path / "linux")
    copy = wsl.copy_scan(scan)
    monkeypatch.setattr(locations, "in_docker", lambda: False)
    monkeypatch.setattr(locations, "windows_path", lambda p: f"C:{p.as_posix()}")
    assert locations.describe(scan) == f"C:{copy.as_posix()}"


def test_windows_paths_can_be_typed_as_target_files(monkeypatch):
    monkeypatch.setattr(wsl, "active", lambda: True)
    monkeypatch.setattr(wsl, "_run", lambda args: "/mnt/c/Users/me/targets.txt"
                        if args == ["wslpath", "-u", r"C:\Users\me\targets.txt"] else None)
    assert wsl.linux_path(r"C:\Users\me\targets.txt") == Path("/mnt/c/Users/me/targets.txt")
    assert wsl.linux_path("example.com") == Path("example.com")


def test_wsl1_is_recognised(monkeypatch):
    monkeypatch.setattr(wsl, "active", lambda: True)
    release = {"value": ""}
    monkeypatch.setattr(wsl.Path, "read_text", lambda self, encoding=None: release["value"])
    for value, expected in (("4.4.0-22621-Microsoft", True),
                            ("6.6.114.1-microsoft-standard-WSL2", False)):
        release["value"] = value
        wsl.is_wsl1.cache_clear()
        assert wsl.is_wsl1() is expected
    wsl.is_wsl1.cache_clear()


def test_windows_programs_are_found_without_windows_path(tmp_path, monkeypatch):
    """Kali's login shell drops Windows' PATH; explorer.exe must still be found."""
    monkeypatch.setattr(wsl.shutil, "which", lambda name: None)
    exe = tmp_path / "explorer.exe"
    exe.write_text("")
    assert wsl._program("explorer.exe", exe) == str(exe)
    assert wsl._program("explorer.exe", tmp_path / "missing.exe") is None


def test_keep_awake_does_nothing_outside_wsl(monkeypatch):
    monkeypatch.setattr(wsl, "active", lambda: False)
    monkeypatch.setattr(wsl.subprocess, "Popen",
                        lambda *a, **k: pytest.fail("started a Windows program"))
    with wsl.keep_awake():
        pass


def test_shortcut_script_quotes_names():
    script = wsl.shortcut_script("kali-linux", "o'neil", "/home/o'neil/.local/bin/footprintx",
                                 r"C:\Users\O'Neil\FootprintX-results")
    assert r"'C:\Users\O''Neil\FootprintX-results'" in script
    assert '-d "kali-linux" -u "o\'\'neil" --cd ~ -e env FOOTPRINTX_LAUNCHER=1' in script


def test_shortcuts_command_outside_wsl(monkeypatch):
    from footprintx.cli import app

    monkeypatch.setattr(wsl, "active", lambda: False)
    result = CliRunner().invoke(app, ["windows-shortcuts"])
    assert result.exit_code == 1


def test_windows_programs_are_not_used_as_tools(monkeypatch):
    from footprintx.integrations import base

    monkeypatch.setenv("PATH", base.os.pathsep.join(["/usr/bin", "/mnt/c/Windows"]))
    monkeypatch.setattr(base, "is_wsl", lambda: True)
    assert "/mnt/c/Windows" not in base._search_dirs()
    assert "/usr/bin" in base._search_dirs()
