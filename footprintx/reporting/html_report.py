"""reports/report.html writer (Jinja2 template in ``templates/``)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from footprintx.core.context import ScanContext
from footprintx.reporting.correlator import AssetNode

_env = Environment(
    loader=PackageLoader("footprintx.reporting", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
)


def write_html_report(context: ScanContext, assets: list[AssetNode], path: Path) -> Path:
    template = _env.get_template("report.html.j2")
    raise NotImplementedError(template.name)
