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
