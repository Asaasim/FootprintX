"""Ubuntu/Debian support: install hints, tool lookup in ~/.local/bin, release downloads."""

import hashlib
import importlib.util
import io
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from footprintx.integrations.base import _search_dirs
from footprintx.integrations.httpx import HttpxIntegration
from footprintx.integrations.nmap import NmapIntegration
from footprintx.utils.platform import PlatformInfo

UBUNTU = PlatformInfo("ubuntu", "Ubuntu 24.04 LTS", ("debian",), False)
SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "github_release.py"


def _load_release_module():
    spec = importlib.util.spec_from_file_location("github_release", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_install_hints_on_ubuntu(monkeypatch):
    monkeypatch.setattr("footprintx.integrations.base.detect_platform", lambda: UBUNTU)
    assert NmapIntegration().installation_hint() == "sudo apt install nmap"
    # httpx-toolkit is a Kali-only package: point at the installer instead of apt
    assert "install.sh" in HttpxIntegration().installation_hint()


def test_tools_found_in_local_bin_without_path(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert _search_dirs() == [str(tmp_path / ".local" / "bin")]


def test_extract_binary_zip_and_tgz():
    mod = _load_release_module()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.md", "x")
        zf.writestr("subfinder", b"ELF-zip")
    assert mod.extract_binary(buf.getvalue(), "s_linux_amd64.zip", "subfinder") == b"ELF-zip"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"ELF-tgz"
        info = tarfile.TarInfo("../../evil/assetfinder")  # path is ignored, never extracted
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    assert mod.extract_binary(buf.getvalue(), "a.tgz", "assetfinder") == b"ELF-tgz"

    with pytest.raises(SystemExit):
        mod.extract_binary(buf.getvalue(), "a.tgz", "naabu")


def test_install_verifies_checksum(monkeypatch, tmp_path):
    mod = _load_release_module()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("naabu", b"ELF")
    archive = buf.getvalue()
    good = hashlib.sha256(archive).hexdigest()
    release = {"tag_name": "v2.7.0", "assets": [
        {"name": "naabu_2.7.0_linux_amd64.zip", "browser_download_url": "zip"},
        {"name": "naabu-checksums.txt", "browser_download_url": "sums"},
    ]}
    sums = {"value": f"{good}  naabu_2.7.0_linux_amd64.zip\n"}
    monkeypatch.setattr(mod, "latest_release", lambda repo: release)
    monkeypatch.setattr(mod, "_get", lambda url, limit=0: archive if url == "zip"
                        else sums["value"].encode())

    dest = tmp_path / "bin" / "naabu"
    assert "checksum verified" in mod.install("x/naabu", r"linux_amd64\.zip$", "naabu", str(dest))
    assert dest.read_bytes() == b"ELF"
    if sys.platform != "win32":
        assert os.access(dest, os.X_OK)

    dest.unlink()
    sums["value"] = f"{'0' * 64}  naabu_2.7.0_linux_amd64.zip\n"
    with pytest.raises(SystemExit, match="checksum mismatch"):
        mod.install("x/naabu", r"linux_amd64\.zip$", "naabu", str(dest))
    assert not dest.exists()


def test_amass_hint_on_ubuntu_is_not_the_installer(monkeypatch):
    from footprintx.integrations.amass import AmassIntegration

    monkeypatch.setattr("footprintx.integrations.base.detect_platform", lambda: UBUNTU)
    assert "install.sh" not in AmassIntegration().installation_hint()
