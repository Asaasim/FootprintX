"""XML report, report-format validation and OWASP ZAP alert import (spec §5.10, §8.2)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import httpx
import pytest

from footprintx.core.config import (
    REPORT_FORMATS,
    ConfigError,
    ModuleConfig,
    Settings,
    load_settings,
)
from footprintx.core.context import ScanContext
from footprintx.core.models import (
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    Target,
    TargetType,
)
from footprintx.core.scope_manager import ScopeManager
from footprintx.modules.proxy import module as proxy_module
from footprintx.modules.proxy.module import ProxyModule
from footprintx.reporting.pipeline import WRITERS
from footprintx.reporting.xml_report import render_xml


def test_every_report_format_has_a_writer():
    assert set(REPORT_FORMATS) == set(WRITERS)


def test_unknown_report_format_is_a_config_error(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("output:\n  formats: [json, htm]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown report format.*htm"):
        load_settings(config)


def test_xml_report_is_well_formed_with_hostile_values():
    data = {
        "tool": "FootprintX",
        "summary": {"hosts": 2, "ok": True, "new_since_last_scan": None},
        "observations": [{"value": "<script>alert(1)</script> & \x1b[31m", "data": {
            "x-powered-by": "PHP", "2fa": "no", "xmlish": "x"}}],
    }
    root = ET.fromstring(render_xml(data).split("?>", 1)[1])
    assert root.tag == "footprintx_report"
    assert root.findtext("summary/hosts") == "2"
    assert root.findtext("summary/ok") == "true"
    assert root.find("summary/new_since_last_scan").get("null") == "true"
    item = root.find("observations/item")
    assert item.findtext("value") == "<script>alert(1)</script> & [31m"
    fields = {f.get("name"): f.text for f in item.iter("field")}
    assert fields == {"2fa": "no", "xmlish": "x"}          # invalid / reserved XML names
    assert item.findtext("data/x-powered-by") == "PHP"


# -- OWASP ZAP -----------------------------------------------------------------------


def _context(tmp_path):
    ctx = ScanContext("s1", tmp_path, Settings(), ScopeManager(["example.com"]),
                      [Target("example.com", TargetType.DOMAIN)])
    ctx.results["http_probe"] = ModuleResult("http_probe", ModuleStatus.SUCCESS, [
        Finding(FindingKind.URL, "https://app.example.com", "http_probe", "app.example.com",
                {"live": True})])
    return ctx


def _fake_zap(monkeypatch, alerts, *, records=(3, 0), status=200):
    seen: dict[str, list[httpx.Request]] = {"api": [], "proxied": []}
    remaining = list(records)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/JSON/"):
            seen["api"].append(request)
            if status != 200:
                return httpx.Response(status)
            if request.url.path == "/JSON/pscan/view/recordsToScan/":
                left = remaining.pop(0) if remaining else 0
                return httpx.Response(200, json={"recordsToScan": str(left)})
            return httpx.Response(200, json={"alerts": alerts})
        seen["proxied"].append(request)
        return httpx.Response(200, text="ok")

    def fake_client(timeout, *, proxy=None, follow_redirects=True, **_):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(proxy_module, "make_client", fake_client)
    monkeypatch.setattr(proxy_module.asyncio, "sleep", _no_sleep)
    return seen


async def _no_sleep(_seconds):
    return None


async def test_zap_alerts_are_imported_as_observations(tmp_path, monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "zap-secret-key-123")
    alerts = [
        {"alert": "Missing Anti-clickjacking Header", "risk": "Medium",
         "url": "https://app.example.com/", "description": "The response does not include "
         "X-Frame-Options.", "cweid": "1021", "confidence": "Medium"},
        {"alert": "Missing Anti-clickjacking Header", "risk": "Medium",   # duplicate
         "url": "https://app.example.com/"},
        {"alert": "Cookie No HttpOnly Flag", "risk": "Low", "param": "sid",
         "url": "https://app.example.com/login"},
        {"alert": "Server Leaks Version", "risk": "Informational",
         "url": "https://other.net/"},                                    # out of scope
    ]
    seen = _fake_zap(monkeypatch, alerts)
    ctx = _context(tmp_path)
    module = ProxyModule(ModuleConfig(enabled=True, api="zap", url="http://127.0.0.1:8080"))
    result = await module.run(ctx)

    assert result.status is ModuleStatus.SUCCESS
    obs = {f.value: f for f in result.findings if f.kind is FindingKind.OBSERVATION}
    assert set(obs) == {"ZAP: Missing Anti-clickjacking Header", "ZAP: Cookie No HttpOnly Flag"}
    assert obs["ZAP: Missing Anti-clickjacking Header"].data["severity"] == "medium"
    assert obs["ZAP: Missing Anti-clickjacking Header"].data["cwe"] == "1021"
    assert obs["ZAP: Cookie No HttpOnly Flag"].data["severity"] == "low"
    assert "(parameter sid)" in obs["ZAP: Cookie No HttpOnly Flag"].data["detail"]
    assert "imported 2 ZAP alerts" in result.notes
    # waited for the passive scanner, then asked for alerts of the scanned origin only
    paths = [r.url.path for r in seen["api"]]
    assert paths.count("/JSON/pscan/view/recordsToScan/") == 2
    alert_calls = [r for r in seen["api"] if r.url.path == "/JSON/alert/view/alerts/"]
    assert [r.url.params["baseurl"] for r in alert_calls] == ["https://app.example.com"]
    assert all(r.headers["X-ZAP-API-Key"] == "zap-secret-key-123" for r in seen["api"])
    assert json.loads((tmp_path / "raw" / "zap_alerts.json").read_text())[0]["cweid"] == "1021"


async def test_zap_api_problems_do_not_fail_the_proxy_step(tmp_path, monkeypatch):
    monkeypatch.delenv("ZAP_API_KEY", raising=False)
    _fake_zap(monkeypatch, [], status=403)
    module = ProxyModule(ModuleConfig(enabled=True, api="zap"))
    result = await module.run(_context(tmp_path))
    assert result.status is ModuleStatus.SUCCESS
    assert any(n.startswith("ZAP API: access denied") for n in result.notes)
    assert not result.findings


async def test_proxy_without_api_does_not_call_zap(tmp_path, monkeypatch):
    seen = _fake_zap(monkeypatch, [])
    result = await ProxyModule(ModuleConfig(enabled=True)).run(_context(tmp_path))
    assert result.status is ModuleStatus.SUCCESS
    assert seen["api"] == [] and len(seen["proxied"]) == 1
