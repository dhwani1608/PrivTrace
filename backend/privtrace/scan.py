"""The one scan pipeline shared by CLI, API and Cloud Run Jobs."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

from privtrace import DISCLAIMER
from privtrace.ai.gateway import AIGateway
from privtrace.core.config import get_settings
from privtrace.findings import SourceCache, extract_findings
from privtrace.fixprompt import PromptBuilder, attach_prompts
from privtrace.models.enums import ManualAnswerValue
from privtrace.models.results import ScanResult, ScanSummary
from privtrace.packs.loader import load_packs, resolve_pack_ids
from privtrace.report.diff import diff_scans
from privtrace.report.fixes import generate_fixes
from privtrace.report.scoring import SCORING_FORMULA, overall_score, risk_level, score_pack
from privtrace.rules.engine import evaluate
from privtrace.scanner.analyze import analyze_path
from privtrace.scanner.facts import CodeFacts
from privtrace.scanner.flow.graph import build_graph, is_risky

if TYPE_CHECKING:
    from privtrace.ci.config import PrivTraceConfig


def run_scan(
    root: Path,
    pack_ids: list[str],
    answers: dict[str, ManualAnswerValue] | None = None,
    *,
    target_label: str | None = None,
    packs_dir: Path | None = None,
    facts: CodeFacts | None = None,
    baseline: ScanResult | None = None,
    fixes: bool = True,
    prompts: bool = True,
    verify_cmd: str | None = None,
    ai: AIGateway | None = None,
    on_stage: Callable[[str], None] | None = None,
    config: PrivTraceConfig | None = None,
    today: date | None = None,
) -> tuple[ScanResult, CodeFacts]:
    """Scan `root` (already on local disk) against the selected packs.

    `config` (a validated `.privtrace.yml`) adds disabled rules, severity overrides, path scope and
    checklist answers. Inline `privtrace-ignore` suppressions apply to every scan.
    """
    from privtrace.ci.policy import apply_policy

    all_packs = load_packs(packs_dir)
    ids = resolve_pack_ids(pack_ids, all_packs)
    packs = [all_packs[i] for i in ids]
    answers = {**(config.manual_answers if config else {}), **(answers or {})}

    stage = on_stage or (lambda _name: None)
    stage("analyzing")
    facts = facts or analyze_path(root, root_name=target_label or root.name)
    stage("evaluating")
    results = evaluate(packs, facts, answers)
    src = SourceCache(root)
    results, suppressions, disabled = apply_policy(results, config, src, facts.files, today=today)
    if fixes:
        generate_fixes(results, packs, facts, root)  # needs the source, so before workspace cleanup
    ai_notes = []
    if ai is not None:
        stage("explaining")
        before = [(r.rule_id, r.status) for r in results]
        ai_notes = ai.enrich(results, packs, facts, root)
        # Structural guarantee (AIEnrichment has no status) + belt-and-braces check.
        if [(r.rule_id, r.status) for r in results] != before:
            raise RuntimeError("AI enrichment changed a rule status")
    findings = extract_findings(results, src)
    file_prompts: dict[str, str] = {}
    fix_all: str | None = None
    if prompts:
        builder = PromptBuilder(packs, facts, src, ids, max_lines=get_settings().max_snippet_lines,
                                verify_cmd=verify_cmd)
        file_prompts, fix_all = attach_prompts(results, findings, builder)
    scores = [score_pack(p, results) for p in packs]
    graph = build_graph(facts.sinks)

    pii_sinks = [s for s in facts.sinks if s.carries_pii]
    result = ScanResult(
        scan_id=uuid.uuid4().hex[:12],
        target=target_label or root.name,
        packs=ids,
        overall_score=overall_score(scores),
        risk_level=risk_level(results),
        pack_scores=scores,
        results=results,
        summary=ScanSummary(
            files_scanned=facts.files_scanned,
            python_files=facts.python_files,
            models_with_pii=sum(1 for m in facts.models if m.fields),
            pii_sinks=len(pii_sinks),
            risky_flows=sum(1 for s in pii_sinks if is_risky(s)),
        ),
        data_flow={**graph.model_dump(), "mermaid": graph.to_mermaid()},
        manual_answers={k: v for k, v in answers.items()},
        findings=findings,
        file_prompts=file_prompts,
        fix_all_prompt=fix_all,
        suppressions=suppressions,
        disabled_rules=disabled,
        scoring_formula=SCORING_FORMULA,
        disclaimer=DISCLAIMER,
    )
    if ai is not None:
        result.ai_used = any(r.ai is not None for r in results) or bool(ai_notes)
        result.ai_model = getattr(ai.transport, "model", None) if result.ai_used else None
        result.ai_classifications = [n.model_dump() for n in ai_notes]
    if baseline is not None:
        result.diff = diff_scans(baseline, result)
    return result, facts
