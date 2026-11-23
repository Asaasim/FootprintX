"""reports/report.xml — the full report model as XML (spec §8.2, optional).

Enable it with ``output.formats: [..., xml]``. The structure mirrors report.json:
dictionary keys become element names (or ``<field name="...">`` when a key is not
a valid XML name), list entries become ``<item>`` elements. Values come from
scanned systems, so control characters that XML 1.0 forbids are removed and
secrets are masked, like in every other output file.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from footprintx.utils.sanitize import redact

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
# Characters not allowed anywhere in an XML 1.0 document.
_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return _INVALID_XML.sub("", str(value))


def _element(parent: ET.Element, key: str, value: Any) -> None:
    if _NAME.match(key) and not key.lower().startswith("xml"):
        node = ET.SubElement(parent, key)
    else:
        node = ET.SubElement(parent, "field", name=_text(key))
    _fill(node, value)


def _fill(node: ET.Element, value: Any) -> None:
    if value is None:
        node.set("null", "true")
    elif isinstance(value, dict):
        for key, child in value.items():
            _element(node, str(key), child)
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            _fill(ET.SubElement(node, "item"), child)
    else:
        node.text = _text(value)


def render_xml(data: dict[str, Any]) -> str:
    root = ET.Element("footprintx_report")
    _fill(root, data)
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def write_xml_report(data: dict[str, Any], path: Path) -> Path:
    path.write_text(redact(render_xml(data)), encoding="utf-8")
    return path
