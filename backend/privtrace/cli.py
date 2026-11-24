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
baseline_app = typer.Typer(help="Manage the committed findings baseline (.privtrace-baseline.json).", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")

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


def resolve_config(root: Path, config: Path | None, all_packs, *, required: bool = False):
    """Load + validate `config` (or `<root>/.privtrace.yml` if present). Raises ConfigError."""
    from privtrace.ci.config import DEFAULT_CONFIG_NAME, load_and_validate

    path = config if config is not None else root / DEFAULT_CONFIG_NAME
    if config is None and not path.exists() and not required:
        return None
    return load_and_validate(path, all_packs)


def _scan_with_config(root: Path, packs: str | None, config: Path | None, packs_dir: Path | None):
    """Scan for CLI helpers. Honours .privtrace.yml (packs, rules, paths, answers) when present."""
    from privtrace.ci.config import ConfigError
    from privtrace.findings import SourceCache
    from privtrace.fixprompt import PromptBuilder
    from privtrace.scan import run_scan

    all_packs = load_packs(packs_dir)
    try:
        cfg = resolve_config(root, config, all_packs)
    except ConfigError as e:
        console.print(f"[red]error:[/red] {escape(str(e))}")
        raise typer.Exit(2) from e
    pack_list = packs.split(",") if packs else (cfg.packs if cfg else ["dpdp", "security"])
    from privtrace.packs.loader import resolve_pack_ids

    ids = resolve_pack_ids(pack_list, all_packs)
    verify = "privtrace ci" if cfg else f"privtrace scan . --packs {','.join(ids)}"
    result, facts = run_scan(root, ids, packs_dir=packs_dir, config=cfg, verify_cmd=verify)
    builder = PromptBuilder([all_packs[i] for i in ids], facts, SourceCache(root), ids, verify_cmd=verify)
    return result, facts, {"builder": builder, "config": cfg}


def _fmt_score(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.0f}"


def _fmt_delta(before: float | None, after: float | None) -> str:
    if before is None or after is None:
        return ""
    d = after - before
    if abs(d) < 0.05:
        return " [dim](=)[/dim]"
    return f" [green]▲{d:.0f}[/green]" if d > 0 else f" [red]▼{abs(d):.0f}[/red]"


def print_ci_summary(run) -> None:
    from privtrace.models.enums import RuleStatus

    rep = run.report
    badge = "[bold green]PASSED ✅[/bold green]" if rep.gate.passed else "[bold red]FAILED ❌[/bold red]"
    console.rule(f"PrivTrace CI gate · {badge}")
    base = rep.baseline.get("source") or "none"
    console.print(f"Baseline: {escape(str(base))}   New: {rep.counts['new']}   Existing: {rep.counts['existing']}   "
                  f"Fixed: {rep.counts['fixed']}   Blocking: {rep.counts['blocking']}")
    t = Table("Framework", "Score", "Minimum")
    t.add_row("Overall", _fmt_score(rep.overall.before) + " → " + _fmt_score(rep.overall.after)
              + _fmt_delta(rep.overall.before, rep.overall.after) if rep.overall.before is not None
              else _fmt_score(rep.overall.after), "" if rep.overall.minimum is None else f"{rep.overall.minimum:g}")
    for p in rep.packs:
        score = (_fmt_score(p.before) + " → " + _fmt_score(p.after) + _fmt_delta(p.before, p.after)
                 if p.before is not None else _fmt_score(p.after))
        t.add_row(p.short_name, score, "" if p.minimum is None else f"{p.minimum:g}")
    console.print(t)
    new = [f for f in run.diff.new]
    if new:
        console.print("[bold]New findings[/bold]")
        for f in new[:20]:
            mark = "[red]✗[/red]" if f.status == RuleStatus.failed else "[yellow]?[/yellow]"
            block = " [red](blocking)[/red]" if f.fingerprint in rep.gate.blocking else ""
            console.print(f"  {mark} {f.severity.value:<8} {f.rule_id:<15} [cyan]{escape(f.location)}[/cyan]{block} [dim]id {f.id}[/dim]")
        if len(new) > 20:
            console.print(f"  … {len(new) - 20} more")
    if run.diff.fixed:
        console.print(f"[green]Fixed: {len(run.diff.fixed)} finding(s) 🎉[/green]")
    for r in rep.gate.reasons:
        console.print(f"[red]• {escape(r)}[/red]")
    for n in rep.gate.notes:
        console.print(f"[dim]• {escape(n)}[/dim]")
    console.print(f"[dim]{rep.disclaimer}[/dim]")


@app.command()
def ci(
    target: Path = typer.Argument(Path("."), help="Repository root (default: current directory)."),
    config: Path | None = typer.Option(None, help="Config file (default: <target>/.privtrace.yml)."),
    packs: str | None = typer.Option(None, help="Override the packs from the config (comma-separated)."),
    base: str | None = typer.Option(None, help="Git ref to compare against, e.g. origin/main (scanned locally)."),
    baseline: Path | None = typer.Option(None, help="Baseline file (default: baseline.file from the config, if present)."),
    json_out: Path | None = typer.Option(None, "--json", help="Write the code-free CI result JSON here."),
    html: Path | None = typer.Option(None, "--html", help="Write the full HTML report here."),
    report_json: Path | None = typer.Option(None, "--report-json", help="Write the full scan JSON (includes redacted prompts)."),
    fail_on: str | None = typer.Option(None, help="Override gate.fail_on_severity: critical|high|medium|low|none."),
    min_score: float | None = typer.Option(None, help="Override gate.min_score."),
    packs_dir: Path | None = typer.Option(None, help="Override the packs directory."),
) -> None:
    """Run the CI compliance gate. Exit codes: 0 passed, 1 gate failed, 2 config or scan error.

        privtrace ci --base origin/main --json out.json --html report.html
    """
    from privtrace.ci.config import ConfigError
    from privtrace.ci.runner import CiOptions, run_ci
    from privtrace.core.redaction import install_log_redaction

    _utf8_stdout()
    install_log_redaction()
    try:
        run = run_ci(CiOptions(root=target.resolve(), config=config, packs=packs, base=base, baseline=baseline,
                               fail_on=fail_on, min_score=min_score, packs_dir=packs_dir),
                     on_stage=lambda s: console.print(f"[dim]… {s}[/dim]"))
        if json_out:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(run.report.model_dump_json(indent=2), encoding="utf-8")
        if report_json:
            write_report(run.head, report_json if report_json.suffix == ".json" else report_json.with_suffix(".json"))
        if html:
            write_report(run.head, html)
        _write_ci_extras(run)
    except typer.Exit:
        raise
    except (ConfigError, PackLoadError) as e:
        console.print(f"[red]error:[/red] {escape(str(e))}")
        raise typer.Exit(2) from e
    except Exception as e:  # an error must never look like a pass
        console.print(f"[red]error:[/red] PrivTrace could not complete the scan ({type(e).__name__}: {escape(str(e))})")
        raise typer.Exit(2) from e
    print_ci_summary(run)
    raise typer.Exit(0 if run.decision.passed else 1)


def _write_ci_extras(run) -> None:
    """Hook for extra CI outputs (SARIF, Markdown, job summary)."""
    return None


@baseline_app.command("update")
def baseline_update(
    target: Path = typer.Option(Path("."), "--target", "-t", exists=True, file_okay=False, help="Repository root."),
    config: Path | None = typer.Option(None, help="Config file (default: <target>/.privtrace.yml)."),
    out: Path | None = typer.Option(None, help="Baseline file (default: baseline.file from the config)."),
    packs_dir: Path | None = typer.Option(None, help="Override the packs directory."),
) -> None:
    """Scan the repository and write the baseline: today's findings become 'existing'.

    Commit the file. In CI, only findings that are not in it count as new.
    """
    from privtrace.ci.baseline import baseline_from_result, write_baseline
    from privtrace.ci.config import ConfigError
    from privtrace.ci.gitutil import head_commit
    from privtrace.core.redaction import install_log_redaction
    from privtrace.scan import run_scan

    install_log_redaction()
    root = target.resolve()
    try:
        all_packs = load_packs(packs_dir)
        cfg = resolve_config(root, config, all_packs, required=True)
        result, _ = run_scan(root, cfg.packs, packs_dir=packs_dir, config=cfg, prompts=False, fixes=False)
    except (ConfigError, PackLoadError) as e:
        console.print(f"[red]error:[/red] {escape(str(e))}")
        raise typer.Exit(2) from e
    dest = out or (root / cfg.baseline.file)
    write_baseline(baseline_from_result(result, source="file", commit=head_commit(root)), dest)
    score = "n/a" if result.overall_score is None else f"{result.overall_score:.0f}"
    console.print(f"[green]wrote {dest}[/green] · {len(result.findings)} finding(s) recorded · overall score {score}")
    console.print("The baseline contains fingerprints, rule ids, paths and scores only: no code.")


@app.command()
def init(
    path: Path = typer.Option(Path(".privtrace.yml"), "--path", help="Where to write the config."),
    packs: str | None = typer.Option(None, help="Comma-separated packs (skips the pack question)."),
    answer: list[str] = typer.Option([], "--answer", help="RULE_ID=yes|no|not_sure (repeatable, skips that question)."),
    skip_checklist: bool = typer.Option(False, "--skip-checklist", help="Do not ask the manual checklist questions."),
    min_score: float | None = typer.Option(None, help="Overall score threshold for the gate."),
    fail_on: str | None = typer.Option(None, help="critical|high|medium|low|none"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
    packs_dir: Path | None = typer.Option(None, help="Override the packs directory."),
) -> None:
    """Create .privtrace.yml: pick packs and walk through the manual checklist once."""
    from privtrace.ci.config import ConfigError, render_config
    from privtrace.models.enums import CheckType, ManualAnswerValue
    from privtrace.packs.loader import resolve_pack_ids

    _utf8_stdout()
    if path.exists() and not force:
        console.print(f"[red]error:[/red] {path} already exists (use --force to overwrite).")
        raise typer.Exit(2)
    try:
        all_packs = load_packs(packs_dir)
    except PackLoadError as e:
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e

    interactive = packs is None
    if packs is None:
        console.rule("PrivTrace init")
        for p in all_packs.values():
            console.print(f"  [bold]{p.id}[/bold]  {escape(p.name)} [dim]({p.jurisdiction}, {len(p.rules)} rules)[/dim]")
        packs = typer.prompt("Which packs apply to this repository? (comma-separated)",
                             default="dpdp-2023,certin-2022,security-baseline")
    try:
        ids = resolve_pack_ids(packs.split(","), all_packs)
    except PackLoadError as e:
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e

    given = _load_answers(None, answer)
    answers: dict[str, ManualAnswerValue] = {}
    questions: dict[str, str] = {}
    choices = {"y": "yes", "yes": "yes", "n": "no", "no": "no", "?": "not_sure", "not_sure": "not_sure",
               "not sure": "not_sure", "s": "", "skip": "", "": ""}
    asked = False
    for pid in ids:
        for rule in all_packs[pid].rules:
            if rule.check_type == CheckType.automated or not rule.question:
                continue
            questions[rule.id] = rule.question
            if rule.id in given:
                answers[rule.id] = given[rule.id]
                continue
            if skip_checklist:
                continue
            if not asked:
                console.print("\nManual checklist: answer y / n / ? (not sure), or press Enter to skip.")
                asked = True
            while True:
                raw = typer.prompt(f"[{rule.id}] {rule.question}", default="", show_default=False).strip().lower()
                if raw in choices:
                    break
                console.print("  please answer y, n, ? or press Enter")
            if choices[raw]:
                answers[rule.id] = ManualAnswerValue(choices[raw])

    if min_score is None:
        min_score = float(typer.prompt("Minimum overall score for the gate", default="70")) if interactive else 70.0
    fail_on = (fail_on or "high").lower()
    if fail_on not in ("critical", "high", "medium", "low", "none"):
        raise typer.BadParameter("--fail-on must be critical, high, medium, low or none")
    try:
        text = render_config(ids, answers, questions, min_score=min_score, fail_on=fail_on)
    except ConfigError as e:  # pragma: no cover - render_config validates its own output
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e
    path.write_text(text, encoding="utf-8")
    console.print(f"[green]wrote {path}[/green] · packs: {', '.join(ids)} · {len(answers)} checklist answer(s)")
    console.print("Next: commit it, then `privtrace baseline update` and add the workflow from "
                  "examples/github/privtrace.yml.")


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
