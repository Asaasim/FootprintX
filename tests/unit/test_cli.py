from typer.testing import CliRunner

from footprintx import __version__
from footprintx.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_modules_list():
    result = runner.invoke(app, ["modules", "list"])
    assert result.exit_code == 0
    assert "subdomains" in result.stdout


def test_scan_requires_a_target():
    assert runner.invoke(app, ["scan"]).exit_code == 2


def test_scan_rejects_unknown_exclude():
    assert runner.invoke(app, ["scan", "-t", "example.com", "--exclude", "bogus"]).exit_code == 2


def test_scan_dry_run_plans_domain_target():
    result = runner.invoke(app, ["scan", "-t", "example.com", "--exclude", "shodan", "--dry-run"])
    assert result.exit_code == 0
    assert "Stage 1" in result.stdout
    assert "shodan" not in result.stdout.split("Execution plan")[1]


def test_scan_does_not_ask_for_permission(tmp_path):
    """Feedback from the user: no permission question — the scan just starts."""
    from footprintx.modules import MODULE_REGISTRY

    result = runner.invoke(app, ["scan", "-t", "example.com", "-o", str(tmp_path),
                                 "-x", ",".join(MODULE_REGISTRY)], input="")
    assert result.exit_code == 0, result.output
    assert "authoris" not in result.output.lower()
    assert any((tmp_path / "example.com").iterdir())


def test_report_is_shown_in_the_terminal_and_again_with_report_command(tmp_path):
    """Feedback from the user: read the report in the command line, no browser needed."""
    from footprintx.modules import MODULE_REGISTRY

    config = tmp_path / "config.yaml"
    config.write_text(f"output:\n  directory: {(tmp_path / 'results').as_posix()}\n",
                      encoding="utf-8")
    scan = runner.invoke(app, ["--config", str(config), "scan", "-t", "example.com",
                               "-x", ",".join(MODULE_REGISTRY)])
    assert scan.exit_code == 0, scan.output
    assert "FootprintX Reconnaissance Report" in scan.output
    assert "Saved on this computer" in scan.output and "report.txt" in scan.output

    again = runner.invoke(app, ["--config", str(config), "report"])
    assert again.exit_code == 0, again.output
    assert "FootprintX Reconnaissance Report" in again.output
    assert "example.com" in again.output

    folder = next((tmp_path / "results" / "example.com").iterdir())
    assert runner.invoke(app, ["--config", str(config), "report", str(folder)]).exit_code == 0
    assert runner.invoke(app, ["--config", str(config), "report", "5"]).exit_code == 1


def test_terminal_report_fits_in_scrollback_but_files_are_complete():
    from footprintx.reporting.text_report import TERMINAL_MAX_HOSTS, render_text_report

    def host(i, issues=0):
        return {"host": f"h{i:03}.example.com", "ips": ["203.0.113.1"], "ports": [],
                "technologies": [], "endpoints": [],
                "urls": [{"url": f"https://h{i:03}.example.com/", "status": 200}],
                "observations": [{"severity": "high", "title": "Exposed"}] * issues}

    hosts = [host(i) for i in range(300)] + [host(999, issues=1)]
    obs = [{"value": f"note {i}", "target": "x", "data": {"severity": "info"}} for i in range(50)]
    obs.insert(0, {"value": "Exposed", "target": "h999", "data": {"severity": "high"}})
    data = {"session_id": "s", "status": "completed", "started_at": "now", "duration": 1,
            "targets": [{"value": "example.com"}], "modules": [], "findings": {},
            "summary": {"hosts": 301, "names_discovered": 301, "live_websites": 301,
                        "open_ports": 0,
                        "observations": {"high": 1, "medium": 0, "low": 0, "info": 50}},
            "observations": obs, "assets": [{"root": "example.com", "hosts": hosts}]}
    short = render_text_report(data, full=False)
    assert "h999.example.com" in short            # the host with an issue is never cut
    assert "Exposed" in short and "note 49" not in short
    assert f"{301 - TERMINAL_MAX_HOSTS} more hosts" in short
    assert len(short.splitlines()) < 500
    full = render_text_report(data)
    assert "h000.example.com" in full and "h299.example.com" in full and "note 49" in full
