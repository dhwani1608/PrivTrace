"""`privtrace ci`: scan HEAD, get a baseline, diff, decide. Used by the CLI and the GitHub Action.

Privacy in CI: with `ai.enabled: false` (the default) no AI gateway is created at all, so nothing
leaves the runner. `--base` uses a local `git worktree`; nothing is fetched.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from privtrace.ci.baseline import Baseline, FindingsDiff, baseline_from_result, diff_findings, load_baseline
from privtrace.ci.config import (
    DEFAULT_CONFIG_NAME,
    ConfigError,
    GateConfig,
    PrivTraceConfig,
    load_and_validate,
    validate_against_packs,
)
from privtrace.ci.gate import GateDecision, evaluate_gate
from privtrace.ci.report import CiReport, build_ci_report
from privtrace.models.results import ScanResult
from privtrace.packs.loader import load_packs

CI_VERIFY_CMD = "privtrace ci"


@dataclass
class CiOptions:
    root: Path
    config: Path | None = None
    packs: str | None = None
    base: str | None = None
    baseline: Path | None = None
    fail_on: str | None = None
    min_score: float | None = None
    packs_dir: Path | None = None
    today: date | None = None


@dataclass
class CiRun:
    cfg: PrivTraceConfig
    head: ScanResult
    base: Baseline | None
    diff: FindingsDiff
    decision: GateDecision
    report: CiReport
    notes: list[str] = field(default_factory=list)
    fix_all_new_prompt: str | None = None


def load_ci_config(opts: CiOptions, all_packs) -> PrivTraceConfig:
    path = opts.config or opts.root / DEFAULT_CONFIG_NAME
    if path.exists():
        cfg = load_and_validate(path, all_packs)
    elif opts.packs and opts.config is None:
        cfg = PrivTraceConfig(packs=[p for p in opts.packs.split(",") if p.strip()])
    else:
        raise ConfigError(f"config file not found: {path}. Run `privtrace init`, or pass --packs.")
    if opts.packs:
        cfg.packs = [p.strip() for p in opts.packs.split(",") if p.strip()]
    errors = validate_against_packs(cfg, all_packs)
    if errors:
        raise ConfigError("configuration is invalid:\n" + "\n".join(f"  - {e}" for e in errors))
    if opts.fail_on is not None or opts.min_score is not None:
        data = cfg.gate.model_dump()
        if opts.fail_on is not None:
            data["fail_on_severity"] = opts.fail_on.lower()
        if opts.min_score is not None:
            data["min_score"] = opts.min_score
        try:
            cfg.gate = GateConfig.model_validate(data)
        except Exception as e:
            raise ConfigError(f"invalid --fail-on / --min-score: {e}") from e
    return cfg


def run_ci(opts: CiOptions, on_stage: Callable[[str], None] | None = None) -> CiRun:
    from privtrace.scan import run_scan

    stage = on_stage or (lambda _s: None)
    root = opts.root.resolve()
    all_packs = load_packs(opts.packs_dir)
    cfg = load_ci_config(opts, all_packs)
    notes: list[str] = []

    gateway = None
    if cfg.ai.enabled:
        from privtrace.ai.gateway import gateway_from_settings

        gateway = gateway_from_settings()
        notes.append("AI explanations enabled by config (redacted snippets are sent to Gemini)." if gateway
                     else "ai.enabled is true but GEMINI_API_KEY / GEMINI_MODEL are not set: no AI was used.")

    stage("scanning HEAD")
    head, facts = run_scan(root, cfg.packs, packs_dir=opts.packs_dir, config=cfg, ai=gateway,
                           verify_cmd=CI_VERIFY_CMD, today=opts.today, prompts=cfg.report.fix_prompts)

    base: Baseline | None = None
    if opts.base:
        from privtrace.ci.gitutil import merge_base, repo_subpath, worktree_at

        stage(f"scanning base {opts.base}")
        commit = merge_base(root, opts.base)
        with worktree_at(root, commit) as wt:
            base_root = wt / repo_subpath(root)
            if base_root.is_dir():
                base_res, _ = run_scan(base_root, cfg.packs, packs_dir=opts.packs_dir, config=cfg,
                                       prompts=False, fixes=False, today=opts.today)
                base = baseline_from_result(base_res, source=f"git:{opts.base}", commit=commit)
            else:
                notes.append(f"{opts.base} does not contain this directory yet: everything is new.")
                base = Baseline(source=f"git:{opts.base}", commit=commit, packs=cfg.packs)
    elif opts.baseline is not None:
        base = load_baseline(opts.baseline)
    elif (root / cfg.baseline.file).exists():
        base = load_baseline(root / cfg.baseline.file)

    diff = diff_findings(base, head)
    decision = evaluate_gate(head, diff, base, cfg.gate)
    decision.notes = notes + decision.notes
    report = build_ci_report(head, base, diff, decision, cfg)
    fix_all_new = None
    if cfg.report.fix_prompts and diff.new:
        from privtrace.core.config import get_settings
        from privtrace.findings import SourceCache
        from privtrace.fixprompt import PromptBuilder

        builder = PromptBuilder([all_packs[i] for i in cfg.packs], facts, SourceCache(root), cfg.packs,
                                max_lines=get_settings().max_snippet_lines, verify_cmd=CI_VERIFY_CMD)
        by_rule = {(r.pack_id, r.rule_id): r for r in head.results}
        pairs = [(by_rule[(f.pack_id, f.rule_id)], f) for f in diff.new if (f.pack_id, f.rule_id) in by_rule]
        fix_all_new = builder.batch_prompt(pairs, top=10, max_chars=15_000)
    return CiRun(cfg=cfg, head=head, base=base, diff=diff, decision=decision, report=report, notes=notes,
                 fix_all_new_prompt=fix_all_new)
