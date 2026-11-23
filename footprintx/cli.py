"""Command-line interface (spec §7).

``footprintx`` with no arguments starts a guided, question-and-answer session for
people who don't want to learn the options. Everything is also available as
regular commands for scripting: ``scan``, ``doctor``, ``modules list``, ``history``.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import sys
import time
import webbrowser
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.status import Status
from rich.table import Table
from rich.text import Text

from footprintx import __version__
from footprintx.core.config import ConfigError, ModuleConfig, Settings, load_settings
from footprintx.core.context import ScanContext
from footprintx.core.logger import setup_logging
from footprintx.core.models import (
    TRACKED_KINDS,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    Target,
    change_key,
)
from footprintx.core.orchestrator import Orchestrator
from footprintx.core.scheduler import ExecutionPlan
from footprintx.core.scope_manager import ScopeManager
from footprintx.core.target_parser import InvalidTargetError, TargetParser
from footprintx.database.history import list_scans
from footprintx.database.storage import HISTORY_DB, Storage
from footprintx.modules import MODULE_REGISTRY, module_config_warnings
from footprintx.reporting.correlator import correlate, count_hosts
from footprintx.utils.dependency_checker import run_doctor


def _use_utf8_output() -> None:
    """Make stdout/stderr UTF-8 so progress marks (✔ ✘) and box characters never crash.

    On Windows, output redirected to a file or pipe uses the ANSI code page
    (e.g. cp1252), which cannot encode them; real consoles are already UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if stream is None or encoding == "utf8" or not hasattr(stream, "reconfigure"):
            continue
        with contextlib.suppress(OSError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")


_use_utf8_output()
console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="footprintx",
    help=(
        "FootprintX — automated reconnaissance & attack surface discovery.\n\n"
        "Run without arguments for a guided scan. Discover. Map. Secure."
    ),
    add_completion=False,
    invoke_without_command=True,
)
modules_app = typer.Typer(help="Inspect reconnaissance modules.", no_args_is_help=True)
app.add_typer(modules_app, name="modules")

#: Plain-language description of each step, shown while it runs.
STEP_LABELS = {
    "subdomains": "finding subdomains",
    "osint": "gathering public information",
    "dns": "looking up DNS records",
    "ip_discovery": "mapping IP addresses",
    "http_probe": "checking websites",
    "port_scanning": "scanning ports",
    "shodan": "querying Shodan",
    "technology_detection": "identifying technologies",
    "web_fuzzing": "searching for hidden files and folders",
    "proxy": "sending URLs to the proxy",
}
SEVERITY_STYLE = {"high": "bold red", "medium": "dark_orange", "low": "yellow", "info": "dim"}


# -- global options -------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"FootprintX {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c",
                     help="Path to config.yaml (default: ~/.config/footprintx/config.yaml, "
                          "then ./config/config.yaml)."),
    ] = None,
    version: Annotated[
        bool,
        typer.Option("--version", "-V", callback=_version_callback, is_eager=True,
                     help="Show version and exit."),
    ] = False,
) -> None:
    ctx.obj = {"config_path": config}
    if ctx.invoked_subcommand is None:
        guided(ctx)


def _settings(ctx: typer.Context) -> Settings:
    try:
        settings = load_settings(ctx.obj["config_path"])
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    _print_config_warnings(settings)
    return settings


def _config_warnings(settings: Settings) -> list[str]:
    return [*settings.warnings, *module_config_warnings(settings)]


def _print_config_warnings(settings: Settings) -> None:
    for warning in _config_warnings(settings):
        err_console.print(f"[yellow]\\[!] Config {escape(str(settings.source))}:[/] "
                          f"{escape(warning)}")


def _parse_exclude(value: str | None) -> set[str]:
    names = {n.strip().lower() for n in (value or "").split(",") if n.strip()}
    unknown = names - MODULE_REGISTRY.keys()
    if unknown:
        raise typer.BadParameter(
            f"unknown module(s): {', '.join(sorted(unknown))}. "
            f"Valid: {', '.join(MODULE_REGISTRY)}",
            param_hint="'--exclude'",
        )
    return names


# -- guided mode ----------------------------------------------------------------


def guided(ctx: typer.Context) -> None:
    """Question-and-answer scan for non-technical users."""
    settings = _settings(ctx)
    setup_logging("ERROR")
    console.print(Panel.fit(
        f"[bold]FootprintX {__version__}[/]\nDiscover. Map. Secure.\n\n"
        "This will map what an organisation exposes on the internet:\n"
        "subdomains, websites, open ports, technologies and possible security issues.",
        border_style="cyan"))

    console.print("\n[bold]1. What do you want to scan?[/]\n"
                  "   A website address ([cyan]example.com[/]), a link "
                  "([cyan]https://example.com[/]), an IP address ([cyan]203.0.113.10[/]),\n"
                  "   a network range ([cyan]192.168.1.0/24[/]), or the path to a .txt file "
                  "with one target per line.\n"
                  "   Several targets can be separated with spaces or commas.")
    parser = TargetParser()
    while True:
        answer = Prompt.ask("   [bold]Target[/]").strip().strip('"').strip("'")
        if not answer:
            continue
        file = Path(answer).expanduser()
        raw = TargetParser.read_file(file) if file.is_file() else re.split(r"[,\s]+", answer)
        targets, invalid = parser.parse_many(raw)
        for value, reason in invalid:
            console.print(f"   [yellow]'{escape(value)}' was not understood: "
                          f"{escape(reason)}[/]")
        if targets:
            break
        console.print("   [yellow]Please try again.[/]")
    console.print("   Targets: " + ", ".join(f"[cyan]{t.value}[/]" for t in targets))

    console.print("\n[bold]2. What kind of scan?[/]\n"
                  "   [cyan]1[/]  Full scan    — everything: also probes websites, scans "
                  "ports and looks for hidden files.\n"
                  "   [cyan]2[/]  Passive scan — public sources only; nothing is sent to the "
                  "target's own servers.")
    passive = Prompt.ask("   [bold]Choose[/]", choices=["1", "2"], default="1") == "2"

    console.print("\n[bold]3. Permission check[/]\n"
                  "   Scanning systems without permission is illegal in most countries.")
    if not Confirm.ask("   Do you have written permission to test these targets?",
                       default=False):
        console.print("\n[yellow]Scan cancelled. Only scan systems you are authorised to "
                      "test.[/]")
        _pause_if_launcher()
        raise typer.Exit(1)

    console.print()
    context = _run_scan(settings, targets, settings.output.directory, set(), passive)
    report = context.reports_dir / "report.html" if context else None
    if report and report.is_file() and _can_open_browser() and \
            Confirm.ask("\nOpen the report in your web browser now?", default=True):
        webbrowser.open(report.resolve().as_uri())
    _pause_if_launcher()


def _can_open_browser() -> bool:
    if sys.platform.startswith("linux"):
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


def _pause_if_launcher() -> None:
    """Keep the terminal window open when started from the desktop menu."""
    if os.environ.get("FOOTPRINTX_LAUNCHER"):
        Prompt.ask("\nPress Enter to close this window", default="", show_default=False)


# -- scan -----------------------------------------------------------------------


@app.command()
def scan(
    ctx: typer.Context,
    target: Annotated[
        list[str] | None,
        typer.Option("--target", "-t", help="Domain, URL, IP or CIDR. Repeatable."),
    ] = None,
    target_list: Annotated[
        Path | None,
        typer.Option("--list", "-l", exists=True, dir_okay=False, readable=True,
                     help="File with one target per line."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Results directory (overrides output.directory)."),
    ] = None,
    exclude: Annotated[
        str | None,
        typer.Option("--exclude", "-x", help="Comma-separated modules to skip, e.g. shodan,proxy."),
    ] = None,
    passive: Annotated[
        bool, typer.Option("--passive", help="Public sources only; don't contact the targets.")
    ] = False,
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", "-s",
                     help="Authorised scope: domain, IP or CIDR, or a file with one per line. "
                          "Repeatable. Default: the targets themselves."),
    ] = None,
    wordlist: Annotated[
        Path | None,
        typer.Option("--wordlist", "-w", exists=True, dir_okay=False, readable=True,
                     help="Wordlist for directory/file discovery."),
    ] = None,
    allow_internal: Annotated[
        bool,
        typer.Option("--allow-internal",
                     help="Also actively scan names that resolve to private/internal "
                          "addresses (internal tests)."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Confirm you are authorised to scan these targets."),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show the execution plan without scanning.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show debug logs.")] = False,
) -> None:
    """Run every applicable, enabled reconnaissance module against the target(s)."""
    settings = _settings(ctx)
    setup_logging("DEBUG" if verbose else "ERROR")
    excluded = _parse_exclude(exclude)
    _apply_overrides(settings, scope, wordlist, allow_internal)

    raw = list(target or [])
    if target_list is not None:
        raw.extend(TargetParser.read_file(target_list))
    if not raw:
        raise typer.BadParameter("provide at least one target", param_hint="'-t' / '-l'")

    targets, invalid = TargetParser().parse_many(raw)
    for value, reason in invalid:
        err_console.print(f"[yellow]\\[!][/] Skipping invalid target {escape(repr(value))}: "
                          f"{escape(reason)}")
    if not targets:
        err_console.print("[red]No valid targets to scan.[/]")
        raise typer.Exit(1)

    output_root = output or settings.output.directory
    if dry_run:
        targets, _ = _apply_scope(settings, targets)
        _print_plan(targets, Orchestrator(settings).plan(targets, excluded, passive), output_root)
        return

    _confirm_authorisation(settings, yes)
    context = _run_scan(settings, targets, output_root, excluded, passive)
    if context is None:
        raise typer.Exit(1)


def _apply_overrides(settings: Settings, scope: list[str] | None, wordlist: Path | None,
                     allow_internal: bool) -> None:
    """Fold command-line options into the loaded settings."""
    for entry in scope or []:
        path = Path(entry).expanduser()
        entries = TargetParser.read_file(path) if path.is_file() else [entry]
        for item in entries:
            try:
                TargetParser().parse(item)
            except InvalidTargetError as exc:
                raise typer.BadParameter(f"{item!r}: {exc}", param_hint="'--scope'") from None
            settings.scope.include.append(item)
    if wordlist is not None:
        current = settings.module_config("web_fuzzing")
        settings.modules["web_fuzzing"] = ModuleConfig(
            **{**current.model_dump(), "wordlist": str(wordlist.resolve())})
    if allow_internal:
        settings.safety.allow_internal_targets = True


def _apply_scope(settings: Settings, targets: list[Target]
                 ) -> tuple[list[Target], ScopeManager]:
    """Drop (and report) targets outside the authorised scope."""
    if not settings.safety.respect_scope:
        return targets, ScopeManager.allow_all(settings.scope.exclude)
    scope = ScopeManager.from_settings(settings.scope, targets)
    for t in targets:
        if not scope.is_in_scope(t.value):
            err_console.print("[yellow]\\[!][/] Skipping out-of-scope target "
                              + escape(repr(t.value)))
    return [t for t in targets if scope.is_in_scope(t.value)], scope


def _run_scan(settings: Settings, targets: list[Target], output_root: Path,
              excluded: set[str], passive: bool) -> ScanContext | None:
    """Scope-check, run with live progress, and print a summary. Shared by both modes."""
    targets, scope = _apply_scope(settings, targets)
    if not targets:
        err_console.print("[red]No in-scope targets to scan.[/]")
        return None

    orchestrator = Orchestrator(settings)
    mode = "passive" if passive else "full"
    console.print(f"[bold]Starting {mode} scan of[/] "
                  + ", ".join(f"[cyan]{escape(t.value)}[/]" for t in targets))
    console.print("[dim]This can take from a few minutes to an hour depending on the size of "
                  "the target. Press Ctrl+C to stop early — results so far are kept.[/]\n")

    progress = _Progress()
    try:
        with console.status("Starting…", spinner="dots") as status:
            progress.status = status
            context = asyncio.run(orchestrator.run(
                targets, scope, output_root, exclude=excluded, passive=passive,
                on_result=progress.finished, on_start=progress.started))
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Scan stopped — partial results and reports were saved "
                          f"under {output_root.expanduser()}.[/]")
        raise typer.Exit(130) from None

    _print_summary(context)
    return context


class _Progress:
    def __init__(self) -> None:
        self.status: Status | None = None
        self.running: list[str] = []
        self.started_at = time.monotonic()

    def started(self, module: str) -> None:
        self.running.append(module)
        self._refresh()

    def finished(self, result: ModuleResult) -> None:
        if result.module in self.running:
            self.running.remove(result.module)
        _print_result(result)
        self._refresh()

    def _refresh(self) -> None:
        if self.status is None:
            return
        minutes = int(time.monotonic() - self.started_at) // 60
        doing = ", ".join(STEP_LABELS.get(m, m) for m in self.running) or "finishing up"
        self.status.update(f"Working: {doing}  [dim]({minutes} min elapsed)[/]")


_STATUS_STYLE = {
    ModuleStatus.SUCCESS: ("✔", "green"),
    ModuleStatus.FAILED: ("✘", "red"),
    ModuleStatus.SKIPPED: ("–", "dim"),
}


def _print_result(result: ModuleResult) -> None:
    mark, style = _STATUS_STYLE.get(result.status, ("?", "white"))
    line = Text(f" {mark} ", style=style)
    line.append(f"{STEP_LABELS.get(result.module, result.module):<40}")
    if result.status is ModuleStatus.SUCCESS:
        line.append(f"{len(result.findings):>5} found", style="bold")
    elif result.status is ModuleStatus.SKIPPED:
        line.append(f"skipped: {result.skip_reason}", style="dim")
    else:
        line.append("failed: " + "; ".join(result.errors)[:150], style="red")
    if result.duration is not None and result.status is not ModuleStatus.SKIPPED:
        line.append(f"  {result.duration:.0f}s", style="dim")
    console.print(line)
    if result.status is ModuleStatus.SUCCESS:
        # problems that didn't fail the step (e.g. a range too large to expand)
        for error in result.errors:
            console.print(Text(f"     ! {error}", style="yellow"))
    if result.status is not ModuleStatus.SKIPPED:
        for note in result.notes:
            console.print(Text(f"     · {note}", style="dim"))


def _print_summary(context: ScanContext) -> None:
    findings = context.findings()
    hosts = count_hosts(correlate(context.targets, findings))
    sites = {f.value for f in findings if f.kind is FindingKind.URL and f.data.get("live")}
    ports = {f.value for f in findings if f.kind is FindingKind.OPEN_PORT}
    observations = {(f.value, f.target): f for f in findings
                    if f.kind is FindingKind.OBSERVATION}

    console.print(f"\n[bold green]Scan {context.status}[/] in "
                  f"{(context.duration or 0) / 60:.1f} minutes.")
    names = len({f.value for f in findings if f.kind is FindingKind.SUBDOMAIN})
    extra = f" (from {names:,} subdomain names in public sources)" if names > hosts else ""
    issues = sum(1 for f in observations.values()
                 if f.data.get("severity") in ("high", "medium", "low"))
    notes = len(observations) - issues
    console.print(f"  {hosts} hosts{extra} · {len(sites)} live websites · {len(ports)} open "
                  f"ports · {issues} issues worth looking at"
                  + (f" (+{notes} informational, see the report)" if notes else ""))
    if context.baseline is not None:
        current = {change_key(f.kind.value, f.value, f.target) for f in findings
                   if f.kind in TRACKED_KINDS}
        new = len(current - context.baseline.keys)
        style = "bold yellow" if new else "dim"
        console.print(f"  [{style}]{new} new since the last scan of these targets[/]")

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    important = sorted((f for f in observations.values()
                        if f.data.get("severity") in ("high", "medium", "low")),
                       key=lambda f: order.get(f.data.get("severity", "info"), 4))
    if len(important) > 10:
        console.print(f"  [dim]Showing the 10 most important of {len(important)} issues.[/]")
        important = important[:10]
    if important:
        table = Table(title="Most important observations", title_justify="left",
                      show_lines=False)
        table.add_column("Severity")
        table.add_column("Issue")
        table.add_column("Where", overflow="fold")
        for f in important:
            sev = f.data.get("severity", "info")
            table.add_row(Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "")), Text(f.value),
                          Text(f.target or ""))
        console.print(table)

    console.print("\n[bold]Full report:[/] " + escape(str(context.reports_dir / "report.html")))
    console.print("[dim]All results: " + escape(str(context.output_dir)) + "[/]")


def _print_plan(targets: list[Target], plan: ExecutionPlan, output_dir: Path) -> None:
    table = Table(title="Targets", title_justify="left")
    table.add_column("Target")
    table.add_column("Type")
    for t in targets:
        table.add_row(Text(t.value), t.type.value)
    console.print(table)

    console.print("\n[bold]Execution plan[/]")
    if not plan:
        console.print("  (no applicable modules)")
    for i, layer in enumerate(plan, start=1):
        console.print(f"  Stage {i}: " + ", ".join(m.name for m in layer))
    console.print("\nOutput directory: " + escape(str(output_dir)))


def _confirm_authorisation(settings: Settings, yes: bool) -> None:
    """Spec §13: active reconnaissance requires explicit authorisation."""
    if yes or not settings.safety.require_authorization:
        return
    if not sys.stdin.isatty():
        err_console.print("[red]Authorisation required:[/] re-run with --yes to confirm you "
                          "are authorised to scan these targets.")
        raise typer.Exit(2)
    if not typer.confirm("Do you have written authorisation to scan these targets?"):
        raise typer.Exit(1)


# -- doctor / modules / history ----------------------------------------------------


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Check installed tools, API keys and configuration."""
    try:
        settings, config_error = load_settings(ctx.obj["config_path"]), None
    except ConfigError as exc:
        settings, config_error = Settings(), str(exc)

    results = run_doctor(settings, config_error)
    if config_error is None:
        _print_config_warnings(settings)
    table = Table(show_header=False, box=None, pad_edge=False)
    for r in results:
        mark = Text("[+]", style="green") if r.ok else Text("[-]", style="red")
        table.add_row(mark, r.name, Text(r.status, style="green" if r.ok else "red"),
                      Text(r.detail, style="dim"))
    console.print(table)

    blocking = [r for r in results if r.required and not r.ok]
    optional = [r for r in results if not r.required and not r.ok]
    if blocking:
        console.print("\n[red]FootprintX cannot run until the items marked as required "
                      "are fixed.[/]")
        raise typer.Exit(1)
    if optional:
        console.print(f"\n[green]Ready to scan.[/] {len(optional)} optional item(s) missing — "
                      "FootprintX still works, the related steps are skipped or use built-in "
                      "fallbacks.")
    else:
        console.print("\n[green]Everything is installed and configured. Ready to scan.[/]")


@modules_app.command("list")
def modules_list(ctx: typer.Context) -> None:
    """List available modules and whether they are enabled."""
    settings = _settings(ctx)
    table = Table(title="Reconnaissance modules", title_justify="left")
    for col in ("Module", "Enabled", "Contacts target", "Depends on", "Description"):
        table.add_column(col)
    for name, cls in MODULE_REGISTRY.items():
        enabled = settings.module_config(name, cls.enabled_by_default).enabled
        table.add_row(
            name,
            Text("yes", style="green") if enabled else Text("no", style="red"),
            "yes" if cls.active else "no",
            ", ".join(cls.depends_on) or "-",
            cls.description,
        )
    console.print(table)


@app.command()
def history(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", "-n", help="How many scans to show.")] = 20,
) -> None:
    """List previous scans and where their reports are."""
    settings = _settings(ctx)
    db = settings.output.directory.expanduser() / HISTORY_DB
    scans = list_scans(Storage(db), limit)
    if not scans:
        console.print("No scans recorded yet in " + escape(str(db.parent)) + ".")
        return
    table = Table(title="Previous scans", title_justify="left")
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("When (UTC)", no_wrap=True)
    table.add_column("Targets", overflow="fold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    table.add_column("Issues", justify="right", no_wrap=True)
    for i, s in enumerate(scans, start=1):
        table.add_row(str(i), str(s["started_at"])[:16].replace("T", " "),
                      Text(s["targets"] or ""), s["status"], str(s["findings"]),
                      str(s["observations"]))
    console.print(table)
    console.print("\n[bold]Reports[/]")
    for i, s in enumerate(scans, start=1):
        report = _display_path(Path(s["output_dir"]) / "reports" / "report.html")
        console.print(Text(f"  {i:>2}  {report}", overflow="fold"))


def _display_path(path: Path) -> str:
    """``path`` relative to the current directory when it is inside it (shorter)."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)
