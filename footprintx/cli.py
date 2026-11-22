"""Command-line interface (spec §7)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from footprintx import __version__
from footprintx.core.config import ConfigError, Settings, load_settings
from footprintx.core.models import Target
from footprintx.core.orchestrator import Orchestrator
from footprintx.core.scheduler import ExecutionPlan
from footprintx.core.scope_manager import ScopeManager
from footprintx.core.target_parser import TargetParser
from footprintx.modules import MODULE_REGISTRY
from footprintx.utils.dependency_checker import run_doctor

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="footprintx",
    help=(
        "FootprintX — automated reconnaissance & attack surface discovery.\n\n"
        "Discover. Map. Secure."
    ),
    no_args_is_help=True,
    add_completion=False,
)
modules_app = typer.Typer(help="Inspect reconnaissance modules.", no_args_is_help=True)
app.add_typer(modules_app, name="modules")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"FootprintX {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c",
            help="Path to config.yaml (default: $FOOTPRINTX_CONFIG or ./config/config.yaml).",
        ),
    ] = None,
    version: Annotated[
        bool,
        typer.Option("--version", "-V", callback=_version_callback, is_eager=True,
                     help="Show version and exit."),
    ] = False,
) -> None:
    ctx.obj = {"config_path": config}


def _settings(ctx: typer.Context) -> Settings:
    try:
        return load_settings(ctx.obj["config_path"])
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/] {exc}")
        raise typer.Exit(2) from exc


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
) -> None:
    """Run every applicable, enabled reconnaissance module against the target(s)."""
    settings = _settings(ctx)
    excluded = _parse_exclude(exclude)

    raw = list(target or [])
    if target_list is not None:
        raw.extend(TargetParser.read_file(target_list))
    if not raw:
        raise typer.BadParameter("provide at least one target", param_hint="'-t' / '-l'")

    targets, invalid = TargetParser().parse_many(raw)
    for value, reason in invalid:
        err_console.print(f"[yellow]\\[!][/] Skipping invalid target {value!r}: {reason}")

    if settings.safety.respect_scope:
        scope = ScopeManager.from_settings(settings.scope, targets)
        for t in targets:
            if not scope.is_in_scope(t.value):
                err_console.print(f"[yellow]\\[!][/] Skipping out-of-scope target {t.value!r}")
        targets = [t for t in targets if scope.is_in_scope(t.value)]

    if not targets:
        err_console.print("[red]No valid, in-scope targets to scan.[/]")
        raise typer.Exit(1)

    plan = Orchestrator(settings).plan(targets, exclude=excluded)
    _print_plan(targets, plan, output or settings.output.directory)

    # TODO (Phase 1): asyncio.run(Orchestrator(settings).run(targets, output_dir, excluded))
    console.print("\n[yellow]Execution engine not implemented yet — plan only.[/]")


def _print_plan(targets: list[Target], plan: ExecutionPlan, output_dir: Path) -> None:
    table = Table(title="Targets", title_justify="left")
    table.add_column("Target")
    table.add_column("Type")
    for t in targets:
        table.add_row(t.value, t.type.value)
    console.print(table)

    console.print("\n[bold]Execution plan[/]")
    if not plan:
        console.print("  (no applicable modules)")
    for i, layer in enumerate(plan, start=1):
        console.print(f"  Stage {i}: " + ", ".join(m.name for m in layer))
    console.print(f"\nOutput directory: {output_dir}")


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Check installed tools, API credentials and configuration."""
    try:
        settings, config_error = load_settings(ctx.obj["config_path"]), None
    except ConfigError as exc:
        settings, config_error = Settings(), str(exc)

    results = run_doctor(settings, config_error)
    table = Table(show_header=False, box=None, pad_edge=False)
    for r in results:
        mark = Text("[+]", style="green") if r.ok else Text("[-]", style="red")
        table.add_row(mark, r.name, Text(r.status, style="green" if r.ok else "red"),
                      Text(r.detail, style="dim"))
    console.print(table)
    console.print("\nDependency check completed.")

    if any(r.required and not r.ok for r in results):
        raise typer.Exit(1)


@modules_app.command("list")
def modules_list(ctx: typer.Context) -> None:
    """List available modules and whether they are enabled."""
    settings = _settings(ctx)
    table = Table(title="Reconnaissance modules", title_justify="left")
    for col in ("Module", "Enabled", "Depends on", "Integrations", "Description"):
        table.add_column(col)
    for name, cls in MODULE_REGISTRY.items():
        enabled = settings.module_config(name, cls.enabled_by_default).enabled
        table.add_row(
            name,
            Text("yes", style="green") if enabled else Text("no", style="red"),
            ", ".join(cls.depends_on) or "-",
            ", ".join(cls.integrations) or "-",
            cls.description,
        )
    console.print(table)
