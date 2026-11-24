"""`CiReport`: the machine-readable result of `privtrace ci` (`--json`).

It is deliberately code-free (no snippets, no prompts): rule ids, severities, paths, line numbers,
fingerprints, scores and the gate decision. That makes it safe to keep as a build artifact and it is
the payload `privtrace ci --upload` sends to the dashboard (see docs/CI_INTEGRATION.md#dashboard-history).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from privtrace import DISCLAIMER, __version__
from privtrace.ci.baseline import Baseline, FindingsDiff
from privtrace.ci.config import PrivTraceConfig
from privtrace.ci.gate import GateDecision
from privtrace.models.results import Finding, ScanResult

CI_REPORT_SCHEMA = 1


class ScoreLine(BaseModel):
    pack_id: str
    short_name: str
    before: float | None = None
    after: float | None = None
    delta: float | None = None
    minimum: float | None = None


class CiFinding(BaseModel):
    id: str
    fingerprint: str
    state: str  # new | existing | fixed
    pack_id: str
    rule_id: str
    title: str
    severity: str
    status: str
    file: str = ""
    line: int = 0
    function: str = ""
    blocking: bool = False


class RunContext(BaseModel):
    """Where the run happened. Filled from CI environment variables or git."""

    provider: str = "local"
    repo: str | None = None
    ref: str | None = None
    sha: str | None = None
    pr_number: int | None = None
    run_url: str | None = None


class CiReport(BaseModel):
    schema_version: int = CI_REPORT_SCHEMA
    tool_version: str = __version__
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    context: RunContext = Field(default_factory=RunContext)
    baseline: dict = Field(default_factory=dict)
    config: dict = Field(default_factory=dict)
    gate: GateDecision
    overall: ScoreLine
    packs: list[ScoreLine] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    findings: list[CiFinding] = Field(default_factory=list)
    suppressions: list[dict] = Field(default_factory=list)
    disabled_rules: list[dict] = Field(default_factory=list)
    disclaimer: str = DISCLAIMER


def _delta(before: float | None, after: float | None) -> float | None:
    return None if before is None or after is None else round(after - before, 1)


def run_context() -> RunContext:
    env = os.environ
    if env.get("GITHUB_ACTIONS") == "true":
        pr = None
        ref = env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME")
        gh_ref = env.get("GITHUB_REF", "")
        if gh_ref.startswith("refs/pull/"):
            try:
                pr = int(gh_ref.split("/")[2])
            except (IndexError, ValueError):
                pr = None
        server = env.get("GITHUB_SERVER_URL", "https://github.com")
        run_url = f"{server}/{env.get('GITHUB_REPOSITORY')}/actions/runs/{env.get('GITHUB_RUN_ID')}" \
            if env.get("GITHUB_RUN_ID") else None
        return RunContext(provider="github", repo=env.get("GITHUB_REPOSITORY"), ref=ref,
                          sha=env.get("GITHUB_SHA"), pr_number=pr, run_url=run_url)
    if env.get("GITLAB_CI") == "true":
        mr = env.get("CI_MERGE_REQUEST_IID")
        return RunContext(provider="gitlab", repo=env.get("CI_PROJECT_PATH"),
                          ref=env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME") or env.get("CI_COMMIT_REF_NAME"),
                          sha=env.get("CI_COMMIT_SHA"), pr_number=int(mr) if mr and mr.isdigit() else None,
                          run_url=env.get("CI_PIPELINE_URL"))
    return RunContext(provider="local")


def _ci_finding(f: Finding, state: str, blocking: set[str]) -> CiFinding:
    return CiFinding(id=f.id, fingerprint=f.fingerprint, state=state, pack_id=f.pack_id, rule_id=f.rule_id,
                     title=f.title, severity=f.severity.value, status=f.status.value, file=f.file, line=f.line,
                     function=f.function, blocking=f.fingerprint in blocking)


def build_ci_report(head: ScanResult, base: Baseline | None, diff: FindingsDiff, decision: GateDecision,
                    cfg: PrivTraceConfig, *, context: RunContext | None = None) -> CiReport:
    gate = cfg.gate
    before = base.pack_scores if base else {}
    packs = [ScoreLine(pack_id=p.pack_id, short_name=p.short_name, before=before.get(p.pack_id), after=p.score,
                       delta=_delta(before.get(p.pack_id), p.score), minimum=gate.min_score_per_pack.get(p.pack_id))
             for p in head.pack_scores]
    blocking = set(decision.blocking)
    findings = [_ci_finding(f, "new", blocking) for f in diff.new]
    findings += [_ci_finding(f, "existing", blocking) for f in diff.existing]
    findings += [CiFinding(id=f.fingerprint[:10], fingerprint=f.fingerprint, state="fixed", pack_id=f.pack_id,
                           rule_id=f.rule_id, title=f.title, severity=f.severity.value, status="fixed",
                           file=f.file, line=f.line) for f in diff.fixed]
    sups = [{k: s[k] for k in ("file", "line", "rule_ids", "reason", "expires", "state", "problem")}
            for s in head.suppressions]
    return CiReport(
        context=context or run_context(),
        baseline={"source": base.source if base else None, "commit": base.commit if base else None,
                  "created_at": base.created_at.isoformat() if base else None},
        config={"packs": cfg.packs, "min_score": gate.min_score, "min_score_per_pack": gate.min_score_per_pack,
                "fail_on_severity": str(gate.fail_on_severity), "new_findings_only": gate.new_findings_only,
                "ai_enabled": cfg.ai.enabled, "disabled_rules": len(head.disabled_rules)},
        gate=decision,
        overall=ScoreLine(pack_id="overall", short_name="Overall", before=base.overall_score if base else None,
                          after=head.overall_score, delta=_delta(base.overall_score if base else None, head.overall_score),
                          minimum=gate.min_score),
        packs=packs,
        counts={"new": len(diff.new), "existing": len(diff.existing), "fixed": len(diff.fixed),
                "blocking": len(blocking),
                "new_failed": sum(1 for f in diff.new if f.status.value == "failed"),
                "suppressions_active": sum(1 for s in head.suppressions if s["state"] == "active"),
                "suppressions_expired": sum(1 for s in head.suppressions if s["state"] == "expired"),
                "suppressions_invalid": sum(1 for s in head.suppressions if s["state"] == "invalid"),
                "disabled_rules": len(head.disabled_rules)},
        findings=findings,
        suppressions=sups,
        disabled_rules=head.disabled_rules,
    )
