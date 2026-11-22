"""Spec features added for v1: change detection, CSV, result files, CLI overrides."""

import csv
import io
import json

from typer.testing import CliRunner

from footprintx.cli import app
from footprintx.core.config import Settings
from footprintx.core.context import ScanContext
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
from footprintx.core.scope_manager import ScopeManager
from footprintx.database.history import previous_scan
from footprintx.database.storage import HISTORY_DB, Storage
from footprintx.modules.base import BaseModule
from footprintx.reporting.aggregator import write_result_files
from footprintx.reporting.csv_report import render_csv

TARGET = Target("example.com", TargetType.DOMAIN)


def finder(*hosts):
    class Finder(BaseModule):
        name, description, applies_to = "subdomains", "", ALL_TARGET_TYPES

        async def run(self, context):
            return ModuleResult(self.name, ModuleStatus.SUCCESS, [
                Finding(FindingKind.SUBDOMAIN, h, "t", "example.com") for h in hosts])
    return Finder


async def test_second_scan_reports_newly_discovered_assets(tmp_path):
    scope = ScopeManager(["example.com"])
    first = await Orchestrator(Settings(), {"subdomains": finder("a.example.com")}).run(
        [TARGET], scope, tmp_path)
    assert first.baseline is None

    second = await Orchestrator(
        Settings(), {"subdomains": finder("a.example.com", "b.example.com")}).run(
        [TARGET], scope, tmp_path)
    assert second.baseline is not None and second.baseline.session_id == first.session_id

    report = json.loads((second.reports_dir / "report.json").read_text())
    assert [n["value"] for n in report["changes"]["new"]] == ["b.example.com"]
    assert report["summary"]["new_since_last_scan"] == 1
    flags = {f["value"]: f.get("new", False) for f in report["findings"]["subdomain"]}
    assert flags == {"a.example.com": False, "b.example.com": True}
    html = (second.reports_dir / "report.html").read_text(encoding="utf-8")
    assert "New since the last scan" in html


async def test_passive_and_full_scans_are_not_compared(tmp_path):
    scope = ScopeManager(["example.com"])
    await Orchestrator(Settings(), {"subdomains": finder("a.example.com")}).run(
        [TARGET], scope, tmp_path, passive=True)
    assert previous_scan(Storage(tmp_path / HISTORY_DB), ["example.com"], passive=False) is None
    assert previous_scan(Storage(tmp_path / HISTORY_DB), ["example.com"], passive=True)


def test_history_db_from_v1_schema_is_migrated(tmp_path):
    import sqlite3
    db = tmp_path / HISTORY_DB
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, "
                     "finished_at TEXT, status TEXT NOT NULL, output_dir TEXT NOT NULL)")
    with Storage(db).connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    assert "mode" in columns


def test_result_files_split_shodan_and_osint(tmp_path):
    findings = [
        Finding(FindingKind.INTEL, "Shodan host data", "shodan", "93.184.215.14", {}),
        Finding(FindingKind.OPEN_PORT, "93.184.215.14:443/tcp", "shodan", "93.184.215.14",
                {"port": 443}),
        Finding(FindingKind.INTEL, "Domain registration", "rdap", "example.com", {}),
        Finding(FindingKind.EMAIL, "info@example.com", "theharvester", "example.com"),
    ]
    names = {p.name for p in write_result_files(tmp_path, findings)}
    assert {"shodan_results.json", "osint_results.json", "open_ports.json"} <= names
    osint = json.loads((tmp_path / "osint_results.json").read_text())
    assert {o["source"] for o in osint} == {"rdap", "theharvester"}
    assert len(json.loads((tmp_path / "shodan_results.json").read_text())) == 2


def test_csv_report_rows():
    item = Finding(FindingKind.URL, "https://example.com", "httpx", "example.com",
                   {"title": "=cmd|' /C calc'!A0", "sources": ["httpx"]}).to_dict()
    obs = Finding(FindingKind.OBSERVATION, "Exposed Git repository", "web_fuzzing",
                  "https://example.com/.git/HEAD", {"severity": "high"}).to_dict()
    rows = list(csv.reader(io.StringIO(render_csv({"observations": [obs],
                                                   "findings": {"url": [item]}}))))
    assert rows[0][0] == "kind"
    assert rows[1][:4] == ["observation", "Exposed Git repository",
                           "https://example.com/.git/HEAD", "high"]
    assert rows[2][1] == "https://example.com"


def test_cli_scope_option_restricts_targets(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")
    result = CliRunner().invoke(app, ["scan", "-t", "example.com", "-t", "other.org",
                                      "--scope", str(scope_file), "--dry-run"])
    assert result.exit_code == 0
    assert "example.com" in result.stdout and "other.org" not in result.stdout.split(
        "Targets")[1].split("Execution plan")[0]


def test_cli_rejects_invalid_scope_entry():
    result = CliRunner().invoke(app, ["scan", "-t", "example.com", "--scope", "not a host",
                                      "--dry-run"])
    assert result.exit_code == 2


def test_report_html_escapes_hostile_content(tmp_path):
    from footprintx.reporting.html_report import write_html_report
    from footprintx.reporting.json_report import build_report_data

    ctx = ScanContext("s", tmp_path, Settings(), ScopeManager(["example.com"]), [TARGET])
    hostile = Finding(FindingKind.URL, "https://example.com", "httpx", "example.com",
                      {"live": True, "title": "<script>alert(1)</script>"})
    path = write_html_report(build_report_data(ctx, [hostile]), tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
