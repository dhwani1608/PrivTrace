# How PrivTrace scores a scan

Scores measure **engineering evidence**, not legal compliance. They are shown on a 0–100 scale where higher means more rules passed.

## Rule statuses

| Status | Meaning | Counts toward the score? |
|---|---|---|
| **passed** | Code evidence (or a "yes" checklist answer) shows the rule is met | ✅ yes (numerator and denominator) |
| **failed** | Code evidence (or a "no" answer) shows it is not met | ✅ yes (denominator only) |
| **needs review** | Heuristic evidence, or a "not sure" / unanswered checklist item | ❌ excluded, listed in the report |
| **not assessable** | Nothing in the code lets us check it | ❌ excluded, shown in coverage |

Heuristic rules (consent capture, minimisation, children's data, third-party sharing) can only produce *passed* or *needs review*, never *failed*.

**Hybrid rules** combine code evidence and a checklist question: a code-level failure always stays *failed*; otherwise the answer decides (yes = passed, no = failed, not sure / unanswered = needs review). A code-level pass becomes *failed* if the answer is "no".

**AI (Gemini) output never changes a status.** It is stored in a separate field that has no status.

## Weights

| Severity | Weight |
|---|---|
| critical | 10 |
| high | 6 |
| medium | 3 |
| low | 1 |

## Framework score

```
score(pack) = 100 × Σ weight(passed rules) / Σ weight(passed + failed rules)
```

If no rule in a pack could be assessed, its score is shown as *n/a*.

## Overall score

A weighted average across the selected frameworks, weighting each by its assessed weight:

```
overall = 100 × Σ_packs passed_weight / Σ_packs assessed_weight
```

A rule that appears in two packs (e.g. "PII in logs" in DPDP and in the Security baseline) counts in both, because both frameworks care about it.

## Risk level

The severity of the most severe **failed** rule across all selected packs: Critical / High / Medium / Low (Low when nothing failed).

## Coverage line

Each framework shows: `X of Y rules checked automatically, Z answered manually, W not assessable from code`, plus the number needing review.

## Worked example

| Rule | Severity | Status | Weight counted |
|---|---|---|---|
| A | critical | passed | 10 / 10 |
| B | high | failed | 0 / 6 |
| C | medium | passed | 3 / 3 |
| D | critical | needs review | excluded |
| E | low | manual "yes" | 1 / 1 |

Score = 100 × 14 / 20 = **70**. Risk level = **High** (rule B). This exact example is a unit test (`tests/test_rules.py::test_score_formula`).
