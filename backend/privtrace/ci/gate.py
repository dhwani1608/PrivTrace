"""The CI gate decision: a pure function of the scan, the baseline diff and the thresholds.

It never calls an LLM and never looks at AI output: pass / fail comes only from deterministic rule
results. `needs_review` findings are reported but never block a merge (they come from heuristics
and unanswered checklist questions; scores already exclude them).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from privtrace.ci.baseline import Baseline, FindingsDiff
from privtrace.ci.config import GateConfig
from privtrace.models.enums import RuleStatus, Severity
from privtrace.models.results import Finding, ScanResult


class GateDecision(BaseModel):
    passed: bool
    reasons: list[str] = Field(default_factory=list, description="Why the gate failed (empty when it passed).")
    notes: list[str] = Field(default_factory=list, description="Context that did not change the outcome.")
    blocking: list[str] = Field(default_factory=list, description="Fingerprints of findings that block the merge.")


def _sev_threshold(gate: GateConfig) -> Severity | None:
    return None if gate.fail_on_severity == "none" else Severity(gate.fail_on_severity)


def blocking_findings(head: ScanResult, diff: FindingsDiff, gate: GateConfig) -> list[Finding]:
    threshold = _sev_threshold(gate)
    if threshold is None:
        return []
    pool = diff.new if gate.new_findings_only else head.findings
    return [f for f in pool if f.status == RuleStatus.failed and f.severity.rank >= threshold.rank]


def evaluate_gate(head: ScanResult, diff: FindingsDiff, base: Baseline | None, gate: GateConfig) -> GateDecision:
    reasons: list[str] = []
    notes: list[str] = []

    blockers = blocking_findings(head, diff, gate)
    if blockers:
        scope = "new " if gate.new_findings_only else ""
        shown = ", ".join(f"{f.rule_id} ({f.location})" for f in blockers[:5])
        more = f" and {len(blockers) - 5} more" if len(blockers) > 5 else ""
        reasons.append(f"{len(blockers)} {scope}failed finding(s) at or above {gate.fail_on_severity}: {shown}{more}")

    if gate.min_score is not None:
        if head.overall_score is None:
            reasons.append("overall score could not be computed (nothing assessable), so the minimum score cannot be met")
        elif head.overall_score < gate.min_score:
            reasons.append(f"overall score {head.overall_score:.0f} is below the minimum {gate.min_score:g}")
    scores = {p.pack_id: p for p in head.pack_scores}
    for pack_id, minimum in gate.min_score_per_pack.items():
        ps = scores.get(pack_id)
        if ps is None:
            continue
        if ps.score is None:
            reasons.append(f"{ps.short_name} score could not be computed, so its minimum {minimum:g} cannot be met")
        elif ps.score < minimum:
            reasons.append(f"{ps.short_name} score {ps.score:.0f} is below its minimum {minimum:g}")

    if gate.new_findings_only and base is None:
        notes.append("No baseline was available, so every finding counts as new. Commit a baseline "
                      "(`privtrace baseline update`) or pass `--base origin/main`.")
    review_new = [f for f in diff.new if f.status == RuleStatus.needs_review]
    if review_new:
        notes.append(f"{len(review_new)} new finding(s) need review; they do not block the merge.")
    return GateDecision(passed=not reasons, reasons=reasons, notes=notes, blocking=[f.fingerprint for f in blockers])
