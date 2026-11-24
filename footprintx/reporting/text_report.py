"""reports/report.txt writer — plain text with the asset tree from spec §9.3."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from footprintx.utils.sanitize import redact

_RULE = "-" * 60
#: The terminal view must fit in a terminal's scrollback (often 1,000 lines), so it
#: shows the most interesting hosts and the first informational notes only.
TERMINAL_MAX_HOSTS = 40
TERMINAL_MAX_INFO = 15


def _terminal_hosts(groups: list[dict[str, Any]]) -> set[int]:
    """ids of the hosts worth showing in the terminal: issues first, then open ports,
    then live websites."""
    hosts = [h for g in groups for h in g["hosts"]]
    ranked = sorted(hosts, key=lambda h: (-len(h["observations"]), -len(h["ports"]),
                                          -len(h["urls"]), h["host"]))
    return {id(h) for h in ranked[:TERMINAL_MAX_HOSTS]}


def render_text_report(data: dict[str, Any], *, full: bool = True) -> str:
    """The report as plain text. ``full=False`` leaves out the complete finding lists
    at the end (shown in the terminal after a scan; they stay in report.txt)."""
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
        f"Live websites: {summary['live_websites']}   Open ports: {summary['open_ports']}"
        + (f" (+{summary['cdn_edge_ports']} on CDN servers, not the organisation's)"
           if summary.get("cdn_edge_ports") else ""),
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
        observations = data["observations"]
        hidden_info = 0
        if not full:
            # Terminal: every real issue, but only the first few informational notes.
            info = [o for o in observations if o["data"].get("severity", "info") == "info"]
            hidden_info = max(0, len(info) - TERMINAL_MAX_INFO)
            keep = {id(o) for o in info[:TERMINAL_MAX_INFO]}
            observations = [o for o in observations
                            if o["data"].get("severity", "info") != "info" or id(o) in keep]
        for o in observations:
            lines.append(f"  [{o['data'].get('severity', 'info').upper():6}] {o['value']}"
                         f" — {o['target']}")
            if o["data"].get("detail"):
                lines.append(f"           {o['data']['detail']}")
        if hidden_info:
            lines.append(f"  … and {hidden_info} more informational notes "
                         "(footprintx report --full, or report.txt)")

    lines += ["", "Attack surface", _RULE]
    shown = _terminal_hosts(data["assets"]) if not full else None
    for group in data["assets"]:
        lines.append(group["root"])
        hosts = group["hosts"]
        hidden = 0
        if shown is not None:
            hidden = len(hosts) - len([h for h in hosts if id(h) in shown])
            hosts = [h for h in hosts if id(h) in shown]
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
        if shown is not None and hidden:
            lines.append(f"  + {hidden} more hosts with less to show "
                         "(footprintx report --full, or report.txt)")
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

    if not full:
        return "\n".join(lines) + "\n"

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
