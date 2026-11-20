"""Rule engine: packs + code facts + manual answers -> rule results."""

from __future__ import annotations

import json

from privtrace.models.enums import CheckType, ManualAnswerValue, RuleStatus
from privtrace.models.results import CheckOutcome, RuleResult
from privtrace.packs.schema import Pack, PackRule
from privtrace.rules.registry import get_check, registered_checks
from privtrace.scanner.facts import CodeFacts


def _manual_status(answer: ManualAnswerValue | None) -> tuple[RuleStatus, str]:
    if answer == ManualAnswerValue.yes:
        return RuleStatus.passed, "Answered 'yes' in the checklist."
    if answer == ManualAnswerValue.no:
        return RuleStatus.failed, "Answered 'no' in the checklist."
    if answer == ManualAnswerValue.not_sure:
        return RuleStatus.needs_review, "Answered 'not sure' in the checklist."
    return RuleStatus.needs_review, "Checklist question not answered."


def combine_hybrid(auto: CheckOutcome, answer: ManualAnswerValue | None) -> tuple[RuleStatus, str]:
    """Code evidence of a failure always wins. Otherwise the answer decides."""
    if auto.status == RuleStatus.failed:
        return RuleStatus.failed, auto.message
    if auto.status == RuleStatus.passed:
        if answer == ManualAnswerValue.no:
            return RuleStatus.failed, auto.message + " Checklist answer: 'no'."
        return RuleStatus.passed, auto.message
    m_status, m_msg = _manual_status(answer)
    return m_status, f"{auto.message} {m_msg}"


def evaluate(packs: list[Pack], facts: CodeFacts, answers: dict[str, ManualAnswerValue] | None = None) -> list[RuleResult]:
    answers = answers or {}
    registered_checks()  # make sure checks are imported
    cache: dict[str, CheckOutcome] = {}
    results: list[RuleResult] = []

    for pack in packs:
        for rule in pack.rules:
            outcome: CheckOutcome | None = None
            if rule.detector:
                key = rule.detector + json.dumps(rule.detector_params, sort_keys=True)
                if key not in cache:
                    try:
                        cache[key] = get_check(rule.detector)(facts, rule.detector_params)
                    except Exception as e:  # a buggy check must not kill the scan
                        cache[key] = CheckOutcome(status=RuleStatus.not_assessable,
                                                  message=f"Check error: {type(e).__name__}")
                outcome = cache[key]

            answer = answers.get(rule.id)
            if rule.check_type == CheckType.automated:
                assert outcome is not None
                status, message = outcome.status, outcome.message
            elif rule.check_type == CheckType.manual:
                status, message = _manual_status(answer)
            else:
                assert outcome is not None
                status, message = combine_hybrid(outcome, answer)

            results.append(_result(pack, rule, status, message, outcome, answer))
    return results


def _result(pack: Pack, rule: PackRule, status: RuleStatus, message: str,
            outcome: CheckOutcome | None, answer: ManualAnswerValue | None) -> RuleResult:
    return RuleResult(
        pack_id=pack.id, rule_id=rule.id, title=rule.title, status=status,
        severity=rule.severity, check_type=rule.check_type, reference=rule.reference,
        reference_verified=rule.reference_verified, source_url=str(rule.source_url),
        why_it_matters=rule.why_it_matters, remediation=rule.remediation, message=message,
        evidence=list(outcome.evidence) if outcome else [], question=rule.question,
        manual_answer=answer if rule.check_type != CheckType.automated else None, tags=rule.tags,
    )
