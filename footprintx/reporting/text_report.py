"""reports/report.txt writer — plain text with the asset tree from spec §9.3."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from footprintx.utils.sanitize import redact

_RULE = "-" * 60


def render_text_report(data: dict[str, Any]) -> str:
    summary = data["summary"]
    obs = summary["observations"]
    lines = [
        "FootprintX Reconnaissance Report",
        "=" * 60,
        f"Session:    {data['session_id']}",
        f"Status:     {data['status']}  ({data.get('mode', 'full')} scan)",
        f"Started:    {data['started_at']}",
        f"Duration:   {_duration(data['duration'])}",
        "Targets:    " + ", ".join(t["value"] for t in data["targets"]),
        "",
        f"Hosts: {summary['hosts']}   Subdomain names found: {summary['names_discovered']}   "
        f"Live websites: {summary['live_websites']}   Open ports: {summary['open_ports']}",
        f"Observations: {obs['high']} high, {obs['medium']} medium, "
        f"{obs['low']} low, {obs['info']} info",
    ]

    changes = data.get("changes")
    if changes:
        lines += ["", f"New since the last scan ({changes['compared_with']})", _RULE]
        for item in changes["new"][:300]:
            target = f"  <- {item['target']}" if item.get("target") else ""
            lines.append(f"  + [{item['kind']}] {item['value']}{target}")
        if not changes["new"]:
            lines.append("  nothing new")

    if data["observations"]:
        lines += ["", "Security observations", _RULE]
        for o in data["observations"]:
            lines.append(f"  [{o['data'].get('severity', 'info').upper():6}] {o['value']}"
                         f" — {o['target']}")
            if o["data"].get("detail"):
                lines.append(f"           {o['data']['detail']}")

    lines += ["", "Attack surface", _RULE]
    for group in data["assets"]:
        lines.append(group["root"])
        hosts = group["hosts"]
        for i, host in enumerate(hosts):
            last = i == len(hosts) - 1
            lines.append(f"  {'└──' if last else '├──'} {host['host']}")
            pad = "      " if last else "  │   "
            details = []
            if host["ips"]:
                details.append("IP: " + ", ".join(host["ips"]))
            for url in host["urls"]:
                title = f" \"{url['title']}\"" if url.get("title") else ""
                details.append(f"{url['url']} [{url.get('status')}]{title}")
            if host["ports"]:
                details.append("Ports: " + ", ".join(
                    f"{p['port']}/{p['protocol']}" + (f" ({p['service']})" if p["service"] else "")
                    for p in host["ports"]))
            if host["technologies"]:
                details.append("Technology: " + ", ".join(host["technologies"]))
            if host["endpoints"]:
                details.append(f"Discovered paths: {len(host['endpoints'])}")
            for o in host["observations"]:
                details.append(f"! [{o['severity']}] {o['title']}")
            for j, detail in enumerate(details):
                lines.append(f"{pad}{'└─' if j == len(details) - 1 else '├─'} {detail}")
        if group.get("other_names"):
            lines.append(f"  + {group['other_names']} more names with nothing else known "
                         "(see subdomains.txt)")
        elif not hosts:
            lines.append("  (nothing discovered)")

    lines += ["", "Modules", _RULE]
    for m in data["modules"]:
        note = m["skip_reason"] or "; ".join(m["errors"] + m["notes"])
        lines.append(f"  [{m['status'].upper():7}] {m['module']:<22} "
                     f"{m['findings']:>5} findings  {note or ''}".rstrip())

    for kind, items in data["findings"].items():
        lines += ["", f"{kind.replace('_', ' ').title()} ({len(items)})", _RULE]
        for item in items:
            sources = ", ".join(item["data"].get("sources", [item["source"]]))
            target = f"  <- {item['target']}" if item.get("target") and \
                item["target"] not in item["value"] else ""
            lines.append(f"  {item['value']}{target}  [{sources}]")
    return "\n".join(lines) + "\n"


def write_text_report(data: dict[str, Any], path: Path) -> Path:
    path.write_text(redact(render_text_report(data)), encoding="utf-8")
    return path


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs}s" if minutes else f"{seconds:.1f}s"
