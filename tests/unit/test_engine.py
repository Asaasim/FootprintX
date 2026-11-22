import asyncio
import json

from footprintx.core.config import ExecutionConfig, Settings
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
from footprintx.core.orchestrator import Orchestrator
from footprintx.core.scheduler import build_execution_plan
from footprintx.core.scope_manager import ScopeManager
from footprintx.modules.base import BaseModule

TARGET = Target("example.com", TargetType.DOMAIN)


def make_module(name, behaviour, depends_on=()):
    class Fake(BaseModule):
        description = "fake"
        applies_to = ALL_TARGET_TYPES

        async def run(self, context):
            return await behaviour(self, context)

    Fake.name = name
    Fake.depends_on = depends_on
    return Fake


async def finds_subdomain(self, context):
    return ModuleResult(self.name, ModuleStatus.SUCCESS, findings=[
        Finding(FindingKind.SUBDOMAIN, "app.example.com", "fake", "example.com")])


async def explodes(self, context):
    raise RuntimeError("boom")


async def not_ready(self, context):
    raise NotImplementedError


async def hangs(self, context):
    await asyncio.sleep(10)


async def sees_dependency(self, context):
    seen = context.findings(FindingKind.SUBDOMAIN)
    return ModuleResult(self.name, ModuleStatus.SUCCESS, notes=[f"saw {len(seen)}"])


def make_context(tmp_path, settings):
    return ScanContext("s1", tmp_path, settings, ScopeManager(["example.com"]), [TARGET])


async def test_failures_are_isolated_and_dependencies_see_findings(tmp_path):
    settings = Settings(execution=ExecutionConfig(module_timeout=0.2))
    modules = [cls() for cls in (
        make_module("a", finds_subdomain),
        make_module("b", explodes),
        make_module("c", not_ready),
        make_module("d", hangs),
        make_module("e", sees_dependency, depends_on=("a", "b")),
    )]
    context = make_context(tmp_path, settings)
    results = await ExecutionEngine(settings).execute(build_execution_plan(modules), context)

    assert results["a"].status is ModuleStatus.SUCCESS
    assert results["b"].status is ModuleStatus.FAILED
    assert "boom" in results["b"].errors[0]
    assert results["c"].status is ModuleStatus.SKIPPED
    assert results["d"].status is ModuleStatus.FAILED
    assert "timed out" in results["d"].errors[0]
    assert results["e"].status is ModuleStatus.SUCCESS
    assert results["e"].notes == ["saw 1"]
    assert all(r.started_at and r.finished_at for r in results.values())


async def test_continue_on_error_false_skips_later_stages(tmp_path):
    settings = Settings(execution=ExecutionConfig(continue_on_error=False))
    modules = [make_module("a", explodes)(), make_module("b", finds_subdomain, ("a",))()]
    context = make_context(tmp_path, settings)
    results = await ExecutionEngine(settings).execute(build_execution_plan(modules), context)
    assert results["b"].status is ModuleStatus.SKIPPED


async def test_orchestrator_writes_session_files_and_reports(tmp_path):
    registry = {
        "a": make_module("a", finds_subdomain),
        "b": make_module("b", explodes),
    }
    orchestrator = Orchestrator(Settings(), registry=registry)
    context = await orchestrator.run(
        [TARGET], ScopeManager(["example.com"]), tmp_path, exclude={"b"})

    out = context.output_dir
    assert out.parent == tmp_path / "example.com"
    assert (out / "targets.txt").read_text() == "example.com\n"
    assert (out / "subdomains.txt").read_text() == "app.example.com\n"
    assert (out / "scan.log").is_file()
    for name in ("report.json", "report.txt", "report.html"):
        assert (out / "reports" / name).is_file()

    info = json.loads((out / "scan_info.json").read_text())
    assert info["status"] == "completed"
    assert info["modules"]["a"]["status"] == "success"
    assert info["modules"]["b"]["skip_reason"] == "excluded on command line"

    report = json.loads((out / "reports" / "report.json").read_text())
    assert report["summary"]["total_findings"] == 1
    assert report["findings"]["subdomain"][0]["data"]["sources"] == ["fake"]
