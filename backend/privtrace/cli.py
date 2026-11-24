"""PrivTrace command-line interface.

    privtrace packs list
    privtrace scan ./repo --packs dpdp,security --out report.html --out report.pdf
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from privtrace import __version__
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
def facts(
    target: Path = typer.Argument(..., exists=True, file_okay=False, help="Local folder."),
    out: Path | None = typer.Option(None, help="Write facts JSON here instead of stdout."),
) -> None:
    """Debug: dump the raw scanner facts (models, sinks, flows, config) as JSON."""
    from privtrace.scanner.analyze import analyze_path

    data = analyze_path(target.resolve()).model_dump_json(indent=2)
    if out:
        out.write_text(data, encoding="utf-8")
        console.print(f"wrote {out}")
    else:
        typer.echo(data)


def _load_answers(answers_file: Path | None, answer: list[str]) -> dict:
    import json

    from privtrace.models.enums import ManualAnswerValue

    raw: dict[str, str] = {}
    if answers_file:
        raw.update(json.loads(answers_file.read_text(encoding="utf-8")))
    for item in answer:
        if "=" not in item:
            raise typer.BadParameter(f"--answer expects RULE_ID=yes|no|not_sure, got {item!r}")
        k, v = item.split("=", 1)
        raw[k.strip()] = v.strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return {k: ManualAnswerValue(v) for k, v in raw.items()}
    except ValueError as e:
        raise typer.BadParameter(f"answers must be yes / no / not_sure: {e}") from e


_STATUS_STYLE = {
    "passed": "[green]passed[/green]",
    "failed": "[red]failed[/red]",
    "needs_review": "[yellow]needs review[/yellow]",
    "not_assessable": "[dim]not assessable[/dim]",
}


def print_summary(result) -> None:
    from privtrace.models.enums import RuleStatus

    score = "n/a" if result.overall_score is None else f"{result.overall_score:.0f}/100"
    console.rule(f"PrivTrace · {result.target}")
    console.print(f"Overall score: [bold]{score}[/bold]   Risk level: [bold]{result.risk_level.value}[/bold]")
    t = Table("Framework", "Score", "Passed", "Failed", "Review", "N/A", "Coverage")
    for ps in result.pack_scores:
        c = ps.coverage
        t.add_row(
            ps.short_name, "n/a" if ps.score is None else f"{ps.score:.0f}",
            str(ps.passed), str(ps.failed), str(ps.needs_review), str(ps.not_assessable),
            f"{c.automated_checked}/{c.total} auto, {c.manual_answered} manual, {c.not_assessable} n/a",
        )
    console.print(t)
    if result.diff:
        d = result.diff
        delta = d.get("overall_delta")
        sign = "" if delta is None else (f"[green]{delta:+.1f}[/green]" if delta >= 0 else f"[red]{delta:+.1f}[/red]")
        console.print(f"Since last scan: {d.get('overall_before')} → {d.get('overall_after')} {sign} · "
                      f"fixed {len(d['fixed'])}, new failures {len(d['regressed'])}")
    failed = [r for r in result.results if r.status == RuleStatus.failed]
    failed.sort(key=lambda r: -r.severity.rank)
    ids = {(f.rule_id, f.file, f.line): f.id for f in getattr(result, "findings", [])}
    for r in failed:
        console.print()
        console.print(f"[red]✗[/red] [bold]{r.rule_id}[/bold] ({r.severity.value}) {escape(r.title)}")
        console.print(f"  {escape(r.message)}")
        for e in r.evidence[:5]:
            fid = ids.get((r.rule_id, e.file, e.line))
            tag = f" [dim]id {fid}[/dim]" if fid else ""
            console.print(f"  [cyan]{escape(e.file)}:{e.line}[/cyan] {escape(e.detail)}{tag}")
        if len(r.evidence) > 5:
            console.print(f"  [dim]… {len(r.evidence) - 5} more[/dim]")
    if failed:
        console.print()
        console.print("[dim]AI fix prompts: `privtrace prompt <id>`, `privtrace prompt <RULE-ID>`, "
                      "`privtrace prompt --file <path>` or `privtrace prompt --all`.[/dim]")
    console.print()
    console.print(f"[dim]{result.disclaimer}[/dim]")


def _history_path(target: Path) -> Path:
    import hashlib

    key = hashlib.sha1(str(target.resolve()).encode()).hexdigest()[:10]
    return Path.cwd() / ".privtrace" / f"last-{target.resolve().name}-{key}.json"


def write_report(result, out: Path) -> Path:
    from privtrace.report.html_report import write_html

    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix.lower() == ".json":
        out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return out
    if out.suffix.lower() == ".pdf":
        from privtrace.report.pdf_report import write_pdf

        return write_pdf(result, out)
    return write_html(result, out if out.suffix.lower() in (".html", ".htm") else out.with_suffix(".html"))


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, file_okay=False, help="Local folder to scan."),
    packs: str = typer.Option("dpdp,security", help="Comma-separated pack ids or aliases."),
    out: list[Path] = typer.Option([], "--out", help="Report file(s): .html, .pdf and/or .json (repeatable)."),
    answers_file: Path | None = typer.Option(None, "--answers", help="JSON file {rule_id: yes|no|not_sure}."),
    answer: list[str] = typer.Option([], "--answer", help="RULE_ID=yes|no|not_sure (repeatable)."),
    baseline: Path | None = typer.Option(None, help="Previous JSON report to diff against."),
    history: bool = typer.Option(True, help="Diff against, and save, the last scan of this folder (.privtrace/)."),
    packs_dir: Path | None = typer.Option(None, help="Override the packs directory."),
    fail_under: float | None = typer.Option(None, help="Exit 1 if the overall score is below this (CI)."),
    ai: bool = typer.Option(True, help="Use Gemini for explanations if GEMINI_API_KEY and GEMINI_MODEL are set."),
) -> None:
    """Scan a local codebase against the selected compliance packs."""
    from privtrace.ai.gateway import gateway_from_settings
    from privtrace.core.redaction import install_log_redaction
    from privtrace.models.results import ScanResult
    from privtrace.scan import run_scan

    install_log_redaction()
    gateway = gateway_from_settings() if ai else None
    if ai and gateway is None:
        console.print("[dim]AI explanations off (set GEMINI_API_KEY and GEMINI_MODEL to enable).[/dim]")

    answers = _load_answers(answers_file, answer)
    prev = None
    hist = _history_path(target)
    if baseline:
        prev = ScanResult.model_validate_json(baseline.read_text(encoding="utf-8"))
    elif history and hist.exists():
        try:
            prev = ScanResult.model_validate_json(hist.read_text(encoding="utf-8"))
        except ValueError:
            prev = None
    try:
        result, _ = run_scan(target.resolve(), packs.split(","), answers, packs_dir=packs_dir,
                             baseline=prev, ai=gateway)
    except PackLoadError as e:
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e
    print_summary(result)
    for o in out:
        console.print(f"Report written to {write_report(result, o)}")
    if history:
        hist.parent.mkdir(parents=True, exist_ok=True)
        hist.write_text(result.model_dump_json(), encoding="utf-8")
    if fail_under is not None and (result.overall_score or 0) < fail_under:
        raise typer.Exit(1)


def _utf8_stdout() -> None:
    import sys

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):  # pragma: no cover - not a TextIOWrapper
            pass


def copy_to_clipboard(text: str) -> bool:
    """Best effort: pbcopy / clip / wl-copy / xclip / xsel. Returns False if none worked."""
    import shutil
    import subprocess
    import sys

    candidates: list[tuple[list[str], bytes]] = []
    if sys.platform == "darwin":
        candidates.append((["pbcopy"], text.encode("utf-8")))
    elif sys.platform.startswith("win"):
        candidates.append((["clip"], b"\xff\xfe" + text.encode("utf-16-le")))
    else:
        candidates += [(["wl-copy"], text.encode()), (["xclip", "-selection", "clipboard"], text.encode()),
                       (["xsel", "--clipboard", "--input"], text.encode())]
    for cmd, data in candidates:
        if shutil.which(cmd[0]) is None:
            continue
        try:
            subprocess.run(cmd, input=data, check=True, timeout=5)
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


@app.command()
def prompt(
    finding: str | None = typer.Argument(None, help="Finding id (or fingerprint prefix) or a rule id like DPDP-SEC-02."),
    target: Path = typer.Option(Path("."), "--target", "-t", exists=True, file_okay=False, help="Folder to scan."),
    file: str | None = typer.Option(None, "--file", help="Print the prompt that fixes every finding in this file."),
    all_: bool = typer.Option(False, "--all", help="Print the batch prompt for the top findings."),
    top: int = typer.Option(10, help="With --all: how many findings to include."),
    packs: str | None = typer.Option(None, help="Comma-separated packs (default: from .privtrace.yml, else dpdp,security)."),
    config: Path | None = typer.Option(None, help="PrivTrace config (default: ./.privtrace.yml in the target if present)."),
    copy: bool = typer.Option(False, "--copy", help="Also copy the prompt to the clipboard."),
    packs_dir: Path | None = typer.Option(None, help="Override the packs directory."),
) -> None:
    """Print a copy-paste AI fix prompt (offline: no AI call is made).

        privtrace prompt 3f2a9c1b0d
        privtrace prompt DPDP-SEC-02
        privtrace prompt --file app/routes.py
        privtrace prompt --all --top 10 > fixes.md
    """
    from privtrace.core.redaction import install_log_redaction
    from privtrace.fixprompt import PromptBuilder

    install_log_redaction()
    _utf8_stdout()
    if sum(bool(x) for x in (finding, file, all_)) != 1:
        raise typer.BadParameter("give exactly one of: a finding id / rule id, --file PATH, or --all")
    root = target.resolve()
    try:
        result, facts, ctx = _scan_with_config(root, packs, config, packs_dir)
    except PackLoadError as e:
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e

    text: str | None = None
    if all_:
        builder: PromptBuilder = ctx["builder"]
        by_rule = {(r.pack_id, r.rule_id): r for r in result.results}
        pairs = [(by_rule[(f.pack_id, f.rule_id)], f) for f in result.findings]
        text = builder.batch_prompt(pairs, top=top)
        if text is None:
            console.print("[green]No failed or needs-review findings: nothing to fix.[/green]")
            raise typer.Exit(0)
    elif file:
        rel = file.replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        text = result.file_prompts.get(rel)
        if text is None:
            console.print(f"[yellow]No findings in {escape(rel)}.[/yellow] Files with findings: "
                          + ", ".join(sorted(result.file_prompts)) or "none")
            raise typer.Exit(1)
    else:
        key = (finding or "").strip()
        rule = next((r for r in result.results if r.rule_id.upper() == key.upper() and r.fix_prompt), None)
        if rule is not None:
            text = rule.fix_prompt
        else:
            matches = [f for f in result.findings if f.fingerprint.startswith(key.lower()) or f.id == key]
            if len(matches) != 1:
                console.print(f"[red]error:[/red] {'no' if not matches else 'more than one'} finding matches {escape(key)!r}. "
                              "Use an id from `privtrace scan` / the JSON report, or a rule id.")
                raise typer.Exit(1)
            text = matches[0].fix_prompt
    typer.echo(text, nl=False)
    if copy:
        if copy_to_clipboard(text or ""):
            typer.echo("Copied to clipboard ✓", err=True)
        else:
            typer.echo("Clipboard not available here; the prompt is printed above.", err=True)


def _scan_with_config(root: Path, packs: str | None, config: Path | None, packs_dir: Path | None):
    """Scan for CLI helpers. Honours .privtrace.yml (packs, rules, paths, answers) when present."""
    from privtrace.fixprompt import PromptBuilder
    from privtrace.findings import SourceCache
    from privtrace.packs.loader import load_packs as _load, resolve_pack_ids
    from privtrace.scan import run_scan

    pack_list = (packs or "dpdp,security").split(",")
    result, facts = run_scan(root, pack_list, packs_dir=packs_dir)
    all_packs = _load(packs_dir)
    ids = resolve_pack_ids(pack_list, all_packs)
    builder = PromptBuilder([all_packs[i] for i in ids], facts, SourceCache(root), ids)
    return result, facts, {"builder": builder}


@app.command()
def verify(
    config: Path = typer.Option(..., exists=True, dir_okay=False, help="Verify config YAML (see demo/verify-*.yaml)."),
    out: Path | None = typer.Option(None, help="Write the verify report as JSON."),
) -> None:
    """Runtime deletion test: create a canary user, delete it, search every store for leftovers.

    Only run against a local or test deployment you own: it writes test data.
    """
    from privtrace.verify.canary import VerifyConfig, run_verify

    cfg = VerifyConfig.load(config)
    console.rule(f"PrivTrace verify · {cfg.name}")
    report = run_verify(cfg)
    if report.error:
        console.print(f"[red]error:[/red] {escape(report.error)}")
    t = Table("Store", "Before delete", "After delete", "Result", "Detail")
    for r in report.results:
        style = {"PASS": "green", "FAIL": "red"}.get(r.status, "yellow")
        fmt = lambda v: "-" if v is None else ("found" if v else "absent")  # noqa: E731
        t.add_row(r.store, fmt(r.found_before_delete), fmt(r.found_after_delete), f"[{style}]{r.status}[/{style}]", escape(r.detail))
    console.print(t)
    console.print(f"canary: {report.canary} · user id: {report.user_id}")
    if out:
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    raise typer.Exit(0 if report.passed else 1)


@packs_app.command("legal-todo")
def packs_legal_todo(
    out: Path = typer.Option(Path("../docs/LEGAL_REVIEW_TODO.md"), help="Output markdown file."),
    packs_dir: Path | None = typer.Option(None),
) -> None:
    """Regenerate docs/LEGAL_REVIEW_TODO.md from unverified pack references."""
    from privtrace.packs.legal_todo import render_legal_todo

    md = render_legal_todo(list(load_packs(packs_dir).values()))
    out.write_text(md, encoding="utf-8")
    console.print(f"wrote {out}")


if __name__ == "__main__":  # pragma: no cover
    app()
