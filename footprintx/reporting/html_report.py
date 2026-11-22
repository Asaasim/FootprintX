"""reports/report.html writer (Jinja2 template in ``templates/``)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from footprintx.utils.sanitize import redact

_env = Environment(
    loader=PackageLoader("footprintx.reporting", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
)


def write_html_report(data: dict[str, Any], path: Path) -> Path:
    html = _env.get_template("report.html.j2").render(report=data)
    path.write_text(redact(html), encoding="utf-8")
    return path
