"""PrivTrace command-line interface.

    privtrace packs list
    privtrace scan ./repo --packs dpdp,security --out report.html
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from privtrace import DISCLAIMER, __version__
from privtrace.packs.loader import PackLoadError, load_packs

app = typer.Typer(help="PrivTrace: scan code against compliance packs.", no_args_is_help=True)
packs_app = typer.Typer(help="Inspect compliance packs.", no_args_is_help=True)
app.add_typer(packs_app, name="packs")

console = Console()


@app.command()
def version() -> None:
    """Print the PrivTrace version."""
    console.print(f"privtrace {__version__}")


@packs_app.command("list")
def packs_list(
    packs_dir: Path | None = typer.Option(None, help="Override the packs directory."),
) -> None:
    """List available compliance packs."""
    try:
        packs = load_packs(packs_dir)
    except PackLoadError as e:
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e
    if not packs:
        console.print("[yellow]No packs found.[/yellow]")
        return
    table = Table("id", "name", "jurisdiction", "version", "auto", "hybrid", "manual")
    for p in packs.values():
        s = p.summary()
        table.add_row(
            s["id"], s["name"], s["jurisdiction"], s["version"],
            str(s["automated"]), str(s["hybrid"]), str(s["manual"]),
        )
    console.print(table)


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Local folder to scan."),
    packs: str = typer.Option("dpdp,security", help="Comma-separated pack ids or aliases."),
    out: Path | None = typer.Option(None, help="Write report (.html or .json)."),
) -> None:
    """Scan a codebase (implemented in later milestones)."""
    console.print("[yellow]scan is not implemented yet (milestone 3+).[/yellow]")
    console.print(f"[dim]{DISCLAIMER}[/dim]")
    raise typer.Exit(1)


if __name__ == "__main__":  # pragma: no cover
    app()
