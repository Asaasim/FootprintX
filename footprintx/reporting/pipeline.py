"""End-of-scan processing: aggregate → normalise → dedupe → result files → reports."""

from __future__ import annotations

from pathlib import Path

from footprintx.core.context import ScanContext
from footprintx.reporting.aggregator import aggregate, write_result_files
from footprintx.reporting.csv_report import write_csv_report
from footprintx.reporting.deduplicator import deduplicate
from footprintx.reporting.html_report import write_html_report
from footprintx.reporting.json_report import build_report_data, write_json_report
from footprintx.reporting.normalizer import normalize
from footprintx.reporting.text_report import write_text_report
from footprintx.reporting.xml_report import write_xml_report

WRITERS = {
    "json": ("report.json", write_json_report),
    "txt": ("report.txt", write_text_report),
    "html": ("report.html", write_html_report),
    "csv": ("findings.csv", write_csv_report),
    "xml": ("report.xml", write_xml_report),
}


def generate_reports(context: ScanContext) -> list[Path]:
    findings = deduplicate(normalize(aggregate(context)))
    written = write_result_files(context.output_dir, findings)

    data = build_report_data(context, findings)
    context.reports_dir.mkdir(parents=True, exist_ok=True)
    for fmt in context.settings.output.formats:
        if fmt in WRITERS:
            filename, writer = WRITERS[fmt]
            written.append(writer(data, context.reports_dir / filename))
    return written
