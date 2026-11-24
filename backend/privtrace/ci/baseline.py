"""Baselines and the new / fixed / existing comparison.

A baseline is the set of finding fingerprints (plus scores) of a reference scan. It comes from:

- a committed `.privtrace-baseline.json` (`privtrace baseline update`), or
- a scan of the PR's base branch in the same CI job (`privtrace ci --base origin/main`).

Both are turned into the same `Baseline` model. A baseline file contains **no code and no
snippets**: fingerprints (hashes of redacted lines), rule ids, severities, file paths, line numbers
and scores only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from privtrace import __version__
from privtrace.ci.config import ConfigError
from privtrace.models.enums import RuleStatus, Severity
from privtrace.models.results import Finding, ScanResult

BASELINE_SCHEMA = 1


class BaselineFinding(BaseModel):
    fingerprint: str
    pack_id: str
    rule_id: str
    title: str = ""
    severity: Severity
    status: RuleStatus
    file: str = ""
    line: int = 0


class Baseline(BaseModel):
    schema_version: int = BASELINE_SCHEMA
    tool: str = "privtrace"
    tool_version: str = __version__
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(default="file", description="'file' or 'git:<ref>'")
    commit: str | None = None
    packs: list[str] = Field(default_factory=list)
    overall_score: float | None = None
    pack_scores: dict[str, float | None] = Field(default_factory=dict)
    findings: list[BaselineFinding] = Field(default_factory=list)


def baseline_from_result(result: ScanResult, *, source: str = "file", commit: str | None = None) -> Baseline:
    return Baseline(
        source=source, commit=commit, packs=list(result.packs), overall_score=result.overall_score,
        pack_scores={p.pack_id: p.score for p in result.pack_scores},
        findings=[BaselineFinding(fingerprint=f.fingerprint, pack_id=f.pack_id, rule_id=f.rule_id, title=f.title,
                                  severity=f.severity, status=f.status, file=f.file, line=f.line)
                  for f in result.findings],
    )


def write_baseline(b: Baseline, path: Path) -> Path:
    path.write_text(b.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline(path: Path) -> Baseline:
    try:
        b = Baseline.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"cannot read baseline {path}: {e}") from e
    except ValidationError as e:
        raise ConfigError(f"{path.name} is not a PrivTrace baseline: {e.errors()[0]['msg']}") from e
    if b.schema_version != BASELINE_SCHEMA:
        raise ConfigError(f"{path.name}: baseline schema {b.schema_version} is not supported "
                          f"(expected {BASELINE_SCHEMA}); run `privtrace baseline update`.")
    return b


class FindingsDiff(BaseModel):
    new: list[Finding] = Field(default_factory=list)
    existing: list[Finding] = Field(default_factory=list)
    fixed: list[BaselineFinding] = Field(default_factory=list)


def diff_findings(base: Baseline | None, head: ScanResult) -> FindingsDiff:
    """Compare by fingerprint. Without a baseline every finding is new."""
    if base is None:
        return FindingsDiff(new=list(head.findings))
    before = {f.fingerprint for f in base.findings}
    after = {f.fingerprint for f in head.findings}
    selected = set(head.packs)
    active_rules = {(r.pack_id, r.rule_id) for r in head.results}  # disabled rules fix nothing either
    return FindingsDiff(
        new=[f for f in head.findings if f.fingerprint not in before],
        existing=[f for f in head.findings if f.fingerprint in before],
        # only report a finding as fixed if its pack is still selected (dropping a pack fixes nothing)
        fixed=[f for f in base.findings if f.fingerprint not in after and f.pack_id in selected
               and (f.pack_id, f.rule_id) in active_rules],
    )
