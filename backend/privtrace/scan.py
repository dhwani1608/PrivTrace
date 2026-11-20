"""The one scan pipeline shared by CLI, API and Cloud Run Jobs."""

from __future__ import annotations

import uuid
from pathlib import Path

from privtrace import DISCLAIMER
from privtrace.models.enums import ManualAnswerValue
from privtrace.models.results import ScanResult, ScanSummary
from privtrace.packs.loader import load_packs, resolve_pack_ids
from privtrace.report.scoring import SCORING_FORMULA, overall_score, risk_level, score_pack
from privtrace.rules.engine import evaluate
from privtrace.scanner.analyze import analyze_path
from privtrace.scanner.facts import CodeFacts
from privtrace.scanner.flow.graph import build_graph, is_risky


def run_scan(
    root: Path,
    pack_ids: list[str],
    answers: dict[str, ManualAnswerValue] | None = None,
    *,
    target_label: str | None = None,
    packs_dir: Path | None = None,
    facts: CodeFacts | None = None,
) -> tuple[ScanResult, CodeFacts]:
    """Scan `root` (already on local disk) against the selected packs."""
    all_packs = load_packs(packs_dir)
    ids = resolve_pack_ids(pack_ids, all_packs)
    packs = [all_packs[i] for i in ids]
    answers = answers or {}

    facts = facts or analyze_path(root, root_name=target_label or root.name)
    results = evaluate(packs, facts, answers)
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
        scoring_formula=SCORING_FORMULA,
        disclaimer=DISCLAIMER,
    )
    return result, facts
