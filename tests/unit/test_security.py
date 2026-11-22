"""Security properties of FootprintX itself (not of the targets it scans)."""

import asyncio
import logging
import sys

import httpx
import pytest

from footprintx.core.config import ModuleConfig, Settings
from footprintx.core.context import ScanContext
from footprintx.core.engine import ExecutionEngine
from footprintx.core.models import (
    ALL_TARGET_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    Target,
    TargetType,
)
from footprintx.core.process_manager import run_command
from footprintx.core.scheduler import build_execution_plan
from footprintx.core.scope_manager import ScopeManager
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.shodan import ShodanError, ShodanIntegration
from footprintx.modules.base import BaseModule
from footprintx.modules.web_fuzzing.module import WebFuzzingModule
from footprintx.reporting.csv_report import neutralise
from footprintx.utils.http import fetch_limited
from footprintx.utils.sanitize import REDACTED, RedactingFilter, clean, clean_text, redact

SECRET = "sk-test-SUPERSECRET-123456"
ESC = "\x1b[31mRED\x1b[0m\x07"


# -- control characters & secrets ------------------------------------------------

def test_clean_text_strips_terminal_escapes_but_keeps_text():
    assert clean_text(f"title {ESC}") == "title [31mRED[0m"
    assert clean_text("tab\tand\nnewline") == "tab\tand\nnewline"
    assert clean({"a": [ESC], "b": {"c": "\x9b2J"}}) == {"a": ["[31mRED[0m"], "b": {"c": "2J"}}


def test_redact_masks_credentials_from_environment(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", SECRET)
    monkeypatch.setenv("SOMETHING_ELSE", SECRET + "x")  # not a credential name: not masked
    assert redact(f"GET https://api.shodan.io/x?key={SECRET}") == \
        f"GET https://api.shodan.io/x?key={REDACTED}"


def test_logging_filter_redacts(monkeypatch, caplog):
    monkeypatch.setenv("SHODAN_API_KEY", SECRET)
    logger = logging.getLogger("footprintx.test")
    caplog.handler.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="footprintx.test"):
        logger.info("calling %s", f"url?key={SECRET}")
    assert SECRET not in caplog.text and REDACTED in caplog.text


async def test_shodan_errors_never_contain_the_api_key(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", SECRET)

    def handler(request):
        return httpx.Response(502)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ShodanError) as err:
            await ShodanIntegration().host(client, "93.184.215.14", retries=0)
    assert SECRET not in str(err.value) and "502" in str(err.value)


async def test_engine_sanitises_module_output(tmp_path, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", SECRET)

    class Leaky(BaseModule):
        name, description, applies_to = "leaky", "", ALL_TARGET_TYPES

        async def run(self, context):
            return ModuleResult(self.name, ModuleStatus.SUCCESS,
                                [Finding(FindingKind.URL, f"https://x.example.com/{ESC}", "t",
                                         data={"title": ESC})],
                                errors=[f"failed: key={SECRET} {ESC}"])

    ctx = ScanContext("s", tmp_path, Settings(), ScopeManager(["example.com"]),
                      [Target("example.com", TargetType.DOMAIN)])
    await ExecutionEngine(Settings()).execute(build_execution_plan([Leaky()]), ctx)
    result = ctx.results["leaky"]
    assert "\x1b" not in result.findings[0].value
    assert "\x1b" not in result.findings[0].data["title"]
    assert SECRET not in result.errors[0] and "\x1b" not in result.errors[0]


# -- hostile servers & tool output ----------------------------------------------

async def test_fetch_limited_caps_response_size():
    def handler(request):
        return httpx.Response(200, content=b"A" * 5_000_000)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        page = await fetch_limited(client, "https://big.example.com/", max_bytes=10_000)
    assert len(page.body) == 10_000 and page.truncated


def test_nmap_xml_entity_expansion_is_rejected():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
            '<nmaprun><host><hostnames><hostname name="&lol2;" type="user"/></hostnames>'
            '</host></nmaprun>')
    assert INTEGRATION_REGISTRY["nmap"].parse(bomb) == []


def test_csv_formula_injection_is_neutralised():
    assert neutralise("=HYPERLINK(\"http://evil\")") == "'=HYPERLINK(\"http://evil\")"
    assert neutralise("+1") == "'+1" and neutralise("@SUM(A1)") == "'@SUM(A1)"
    assert neutralise("app.example.com") == "app.example.com"


def test_fuzzing_never_uses_state_changing_methods():
    module = WebFuzzingModule(ModuleConfig(method="DELETE"))
    ctx = ScanContext("s", None, Settings(), ScopeManager(["example.com"]), [])  # type: ignore[arg-type]
    assert module._options(ctx)["method"] == "GET"
    assert WebFuzzingModule(ModuleConfig(method="head"))._options(ctx)["method"] == "HEAD"


# -- process handling --------------------------------------------------------------

async def test_timeout_keeps_partial_output_and_kills_the_tool():
    script = "import sys, time; print('partial-result', flush=True); time.sleep(30)"
    result = await run_command([sys.executable, "-c", script], timeout=2)
    assert result.timed_out
    assert "partial-result" in result.stdout
    assert result.duration < 15


async def test_cancellation_kills_child_process():
    task = asyncio.create_task(run_command([sys.executable, "-c", "import time; time.sleep(30)"],
                                           timeout=60))
    await asyncio.sleep(1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_target_names_cannot_inject_options():
    """Targets are passed as argv items, never through a shell; hostnames that look
    like options or shell syntax are rejected by validation before reaching a tool."""
    from footprintx.core.target_parser import InvalidTargetError, TargetParser

    for hostile in ["-oX /tmp/x", "--script=evil", "example.com;id", "$(id).example.com",
                    "`id`.example.com", "example.com && rm -rf ~"]:
        with pytest.raises(InvalidTargetError):
            TargetParser().parse(hostile)
