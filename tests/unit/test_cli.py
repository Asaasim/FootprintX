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


def test_scan_requires_authorisation_when_not_interactive(tmp_path):
    result = runner.invoke(app, ["scan", "-t", "example.com", "-o", str(tmp_path)])
    assert result.exit_code == 2
    assert "--yes" in result.stderr
    assert not any(tmp_path.iterdir())
