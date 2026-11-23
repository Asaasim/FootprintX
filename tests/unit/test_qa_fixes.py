"""Regression tests for issues found in QA: Windows output encoding, misspelt
config keys, crt.sh outages, terminal summary and history layout."""

from __future__ import annotations

import io
import subprocess
import sys

import httpx
import pytest
from typer.testing import CliRunner

from footprintx.cli import app
from footprintx.core.config import Settings, load_settings
from footprintx.integrations.crtsh import CrtShError, CrtShIntegration
from footprintx.modules import module_config_warnings


def test_redirected_output_on_a_non_utf8_code_page_does_not_crash():
    """Windows redirects stdout with the ANSI code page (cp1252); ✔ must not crash."""
    code = ("import io, sys; "
            "sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='cp1252'); "
            "import footprintx.cli as c; c.console.print('\u2714 done'); "
            "sys.stdout.flush(); print(sys.stdout.encoding, file=sys.stderr)")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          check=False)
    assert done.returncode == 0, done.stderr
    assert done.stderr.strip() == "utf-8"


def test_unknown_config_keys_are_reported(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "execution:\n  concurency: 5\n"
        "modles: {}\n"
        "modules:\n  dns: {enabeld: false, record_types: [A]}\n  nosuch: {enabled: true}\n",
        encoding="utf-8")
    settings = load_settings(config)
    warnings = [*settings.warnings, *module_config_warnings(settings)]
    assert "unknown setting 'execution.concurency' (did you mean 'concurrency'?) is ignored" \
        in warnings
    assert "unknown section 'modles' (did you mean 'modules'?) is ignored" in warnings
    assert "unknown setting 'modules.dns.enabeld' (did you mean 'enabled'?) is ignored" \
        in warnings
    assert any(w.startswith("unknown module 'modules.nosuch'") for w in warnings)
    assert not any("record_types" in w for w in warnings)


def test_shipped_config_has_no_unknown_keys():
    settings = load_settings("config/config.yaml")
    assert settings.warnings == []
    assert module_config_warnings(settings) == []


def test_cli_prints_config_warnings(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("modules:\n  dns: {enabeld: false}\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["-c", str(config), "scan", "-t", "example.com",
                                      "--dry-run"])
    assert result.exit_code == 0
    assert "modules.dns.enabeld" in result.output


async def test_crtsh_outage_is_retried_and_explained(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(502)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    client = CrtShIntegration()
    client.backoff = 0
    with pytest.raises(CrtShError, match="temporarily unavailable .*HTTP 502"):
        await client.fetch("example.com", timeout=5, retries=0)
    assert len(calls) == CrtShIntegration.min_attempts


async def test_crtsh_recovers_after_a_transient_error(monkeypatch):
    responses = iter([httpx.Response(503), httpx.Response(200, text="[]")])
    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(
        transport=httpx.MockTransport(lambda request: next(responses))))
    client = CrtShIntegration()
    client.backoff = 0
    assert await client.fetch("example.com", timeout=5, retries=0) == "[]"


def test_settings_warnings_not_serialised():
    assert "warnings" not in Settings().model_dump()


def test_io_wrapper_reconfigure_supported():
    # _use_utf8_output relies on TextIOWrapper.reconfigure
    assert hasattr(io.TextIOWrapper(io.BytesIO()), "reconfigure")
