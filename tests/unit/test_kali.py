from footprintx.integrations.httpx import HttpxIntegration
from footprintx.utils import platform as platform_mod
from footprintx.utils.platform import PlatformInfo, parse_os_release
from footprintx.utils.wordlists import resolve_wordlist

KALI_OS_RELEASE = '''PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2026.4"
ID=kali
ID_LIKE=debian
'''


def test_parse_os_release_detects_kali():
    values = parse_os_release(KALI_OS_RELEASE)
    info = PlatformInfo(values["ID"], values["PRETTY_NAME"], (values["ID_LIKE"],), False)
    assert info.is_kali and info.uses_apt
    assert info.os_name == "Kali GNU/Linux Rolling"


def test_apt_install_hint_on_kali(monkeypatch):
    kali = PlatformInfo("kali", "Kali GNU/Linux Rolling", ("debian",), False)
    monkeypatch.setattr("footprintx.integrations.base.detect_platform", lambda: kali)
    assert HttpxIntegration().installation_hint() == "sudo apt install httpx-toolkit"


def test_go_install_hint_elsewhere(monkeypatch):
    other = PlatformInfo("arch", "Arch Linux", (), False)
    monkeypatch.setattr("footprintx.integrations.base.detect_platform", lambda: other)
    assert HttpxIntegration().installation_hint().startswith("go install")


def test_httpx_prefers_kali_binary_name(monkeypatch):
    found = {"httpx-toolkit": "/usr/bin/httpx-toolkit", "httpx": "/usr/bin/httpx"}
    monkeypatch.setattr(HttpxIntegration, "_find_on_path",
                        lambda self, binary: found.get(binary))
    assert HttpxIntegration().locate() == "/usr/bin/httpx-toolkit"


def test_resolve_wordlist(tmp_path):
    seclists = tmp_path / "common.txt"
    seclists.write_text("admin\n")
    missing = tmp_path / "missing.txt"
    assert resolve_wordlist(None, (missing, seclists)) == seclists
    assert resolve_wordlist(None, (missing,)) is None
    assert resolve_wordlist(str(seclists)) == seclists
    assert resolve_wordlist(str(missing), (seclists,)) is None


def test_detect_platform_is_cached():
    assert platform_mod.detect_platform() is platform_mod.detect_platform()
