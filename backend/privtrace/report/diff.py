"""What changed between two scans (rescan after fixes)."""

from __future__ import annotations

from privtrace.models.enums import RuleStatus
from privtrace.models.results import ScanResult


def diff_scans(previous: ScanResult, current: ScanResult) -> dict:
    prev = {(r.pack_id, r.rule_id): r for r in previous.results}
    fixed, regressed, still_failing, changed = [], [], [], []
    for r in current.results:
        key = (r.pack_id, r.rule_id)
        old = prev.get(key)
        if old is None:
            continue
        item = {"pack_id": r.pack_id, "rule_id": r.rule_id, "title": r.title, "from": old.status.value,
                "to": r.status.value, "severity": r.severity.value}
        if old.status == RuleStatus.failed and r.status != RuleStatus.failed:
            fixed.append(item)
        elif old.status != RuleStatus.failed and r.status == RuleStatus.failed:
            regressed.append(item)
        elif old.status == r.status == RuleStatus.failed:
            still_failing.append(item)
        elif old.status != r.status:
            changed.append(item)

    prev_scores = {p.pack_id: p.score for p in previous.pack_scores}
    pack_deltas = []
    for p in current.pack_scores:
        before = prev_scores.get(p.pack_id)
        pack_deltas.append({
            "pack_id": p.pack_id, "short_name": p.short_name, "before": before, "after": p.score,
            "delta": None if before is None or p.score is None else round(p.score - before, 1),
        })
    ob, oa = previous.overall_score, current.overall_score
    return {
        "previous_scan_id": previous.scan_id,
        "previous_target": previous.target,
        "previous_created_at": previous.created_at.isoformat(),
        "overall_before": ob,
        "overall_after": oa,
        "overall_delta": None if ob is None or oa is None else round(oa - ob, 1),
        "risk_before": previous.risk_level.value,
        "risk_after": current.risk_level.value,
        "packs": pack_deltas,
        "fixed": fixed,
        "regressed": regressed,
        "still_failing": still_failing,
        "other_changes": changed,
    }
