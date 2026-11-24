"""CI outputs: SARIF 2.1.0, PR comment / job summary Markdown, GitLab Code Quality JSON.

All of them are rendered from the same deterministic data. Only the Markdown carries fix prompts
(redacted, capped); SARIF and Code Quality carry rule metadata, locations and fingerprints.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from privtrace import __version__
from privtrace.fixprompt import PROMPT_DISCLAIMER
from privtrace.models.enums import RuleStatus, Severity
from privtrace.models.results import Finding, RuleResult

if TYPE_CHECKING:
    from privtrace.ci.runner import CiRun

COMMENT_MARKER = "<!-- privtrace-gate -->"
GITHUB_COMMENT_LIMIT = 60_000  # GitHub's hard limit is 65 536 characters
INFO_URI = "https://github.com/dhwani1608/PrivTrace"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SARIF_LEVEL = {Severity.critical: "error", Severity.high: "error", Severity.medium: "warning", Severity.low: "note"}
SECURITY_SEVERITY = {Severity.critical: "9.5", Severity.high: "8.0", Severity.medium: "5.5", Severity.low: "3.0"}
CODEQUALITY_SEVERITY = {Severity.critical: "blocker", Severity.high: "critical", Severity.medium: "major", Severity.low: "minor"}
SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦"}


def _fence(text: str) -> str:
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _location_or_config(f: Finding) -> tuple[str, int]:
    """Project-level findings (no file) are anchored to the config file so SARIF accepts them."""
    return (f.file, max(1, f.line)) if f.file else (".privtrace.yml", 1)


# ---------------------------------------------------------------- SARIF
def to_sarif(run: CiRun) -> dict[str, Any]:
    head = run.head
    by_rule: dict[tuple[str, str], RuleResult] = {(r.pack_id, r.rule_id): r for r in head.results}
    states = {f.fingerprint: "new" for f in run.diff.new} | {f.fingerprint: "unchanged" for f in run.diff.existing}
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for f in head.findings:
        rr = by_rule.get((f.pack_id, f.rule_id))
        if f.rule_id not in rule_index and rr is not None:
            rule_index[f.rule_id] = len(rules)
            ref = rr.reference + ("" if rr.reference_verified else " (reference pending review)")
            help_md = (f"**Why it matters.** {rr.why_it_matters}\n\n**How to fix.** {rr.remediation}\n\n"
                       f"**Reference.** {ref}\n\n_Engineering evidence, not legal advice._")
            rules.append({
                "id": rr.rule_id,
                "name": re.sub(r"[^A-Za-z0-9]", "", rr.title.title())[:100] or rr.rule_id,
                "shortDescription": {"text": rr.title},
                "fullDescription": {"text": rr.why_it_matters},
                "help": {"text": f"Why it matters: {rr.why_it_matters}\nHow to fix: {rr.remediation}\nReference: {ref}",
                         "markdown": help_md},
                "helpUri": rr.source_url,
                "defaultConfiguration": {"level": SARIF_LEVEL[rr.severity]},
                "properties": {
                    "tags": ["privacy", "privtrace", rr.pack_id, *rr.tags],
                    "security-severity": SECURITY_SEVERITY[rr.severity],
                    "precision": "high" if rr.check_type.value == "automated" else "medium",
                    "problem.severity": "error" if rr.severity.rank >= 3 else "warning",
                },
            })
        if f.rule_id not in rule_index:
            continue
        path, line = _location_or_config(f)
        level = SARIF_LEVEL[f.severity] if f.status == RuleStatus.failed else "note"
        status = "failed" if f.status == RuleStatus.failed else "needs review"
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": level,
            "message": {"text": f"{f.title} ({status}). {f.detail}".strip()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": line},
            }}],
            "partialFingerprints": {"privtrace/v1": f.fingerprint},
            "baselineState": states.get(f.fingerprint, "new"),
            "properties": {"pack": f.pack_id, "severity": f.severity.value, "status": f.status.value,
                           "function": f.function},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "PrivTrace", "version": __version__, "semanticVersion": __version__,
                                "informationUri": INFO_URI, "rules": rules}},
            "automationDetails": {"id": "privtrace/" + ",".join(run.cfg.packs) + "/"},
            "columnKind": "unicodeCodePoints",
            "results": results,
        }],
    }


# ---------------------------------------------------------------- GitLab Code Quality
def to_codequality(run: CiRun) -> list[dict[str, Any]]:
    out = []
    for f in run.head.findings:
        path, line = _location_or_config(f)
        out.append({
            "type": "issue",
            "check_name": f.rule_id,
            "description": f"{f.rule_id}: {f.title}" + (" (needs review)" if f.status == RuleStatus.needs_review else ""),
            "categories": ["Security"],
            "fingerprint": f.fingerprint,
            "severity": CODEQUALITY_SEVERITY[f.severity] if f.status == RuleStatus.failed else "info",
            "location": {"path": path, "lines": {"begin": line}},
        })
    return out


# ---------------------------------------------------------------- Markdown (PR comment + job summary)
def _score(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.0f}"


def _change(before: float | None, after: float | None) -> str:
    if before is None or after is None:
        return "–"
    d = after - before
    if abs(d) < 0.05:
        return f"{_score(before)} → {_score(after)} (=)"
    arrow = "▲" if d > 0 else "▼"
    return f"{_score(before)} → {_score(after)} {arrow}{abs(d):.0f}"


def _details(summary: str, body: str) -> str:
    return f"<details><summary>{summary}</summary>\n\n{body}\n\n</details>\n"


def _prompt_block(text: str) -> str:
    fence = _fence(text)
    return f"{fence}markdown\n{text.rstrip()}\n{fence}"


def render_markdown(run: CiRun, *, report_url: str | None = None, max_prompts: int | None = None,
                    with_prompts: bool = True, limit: int = GITHUB_COMMENT_LIMIT) -> str:
    """The sticky PR comment. Shrinks prompt sections until it fits GitHub's size limit."""
    cap = run.cfg.report.max_prompts_in_comment if max_prompts is None else max_prompts
    if not (with_prompts and run.cfg.report.fix_prompts):
        cap = 0
    include_all = True
    while True:
        text = _render(run, report_url=report_url, n_prompts=cap, include_fix_all=include_all)
        if len(text) <= limit:
            return text
        if include_all and cap <= 3:
            include_all = False
        elif cap > 0:
            cap -= 1
        else:
            return text[: limit - 200] + "\n\n…(truncated: see the full report)\n"


def _render(run: CiRun, *, report_url: str | None, n_prompts: int, include_fix_all: bool) -> str:
    rep = run.report
    g = rep.gate
    out: list[str] = [COMMENT_MARKER]
    if g.passed:
        out.append("## ✅ PrivTrace gate passed")
    else:
        out.append("## ❌ PrivTrace gate failed")
    base_src = rep.baseline.get("source")
    base_txt = {None: "no baseline (every finding counts as new)"}.get(base_src, f"compared with `{base_src}`")
    out.append(f"\n**{rep.counts['new']}** new · **{rep.counts['fixed']}** fixed · {rep.counts['existing']} existing "
               f"· {base_txt} · packs: {', '.join(f'`{p}`' for p in rep.config['packs'])}\n")

    out.append("| Framework | Score | Change | Minimum |\n|---|---:|---|---:|")
    out.append(f"| **Overall** | **{_score(rep.overall.after)}** | {_change(rep.overall.before, rep.overall.after)} | "
               f"{'' if rep.overall.minimum is None else f'{rep.overall.minimum:g}'} |")
    for p in rep.packs:
        out.append(f"| {p.short_name} | {_score(p.after)} | {_change(p.before, p.after)} | "
                   f"{'' if p.minimum is None else f'{p.minimum:g}'} |")

    if g.reasons:
        out.append("\n**Why the gate failed**")
        out += [f"- {r}" for r in g.reasons]

    new = run.diff.new
    if new:
        blocking = set(g.blocking)
        out.append(f"\n### New findings ({len(new)})\n")
        out.append("| Severity | Rule | Location | |\n|---|---|---|---|")
        for f in new[:50]:
            status = "**blocking**" if f.fingerprint in blocking else ("needs review" if f.status == RuleStatus.needs_review else "")
            out.append(f"| {SEV_ICON[f.severity.value]} {f.severity.value} | `{f.rule_id}` {f.title} | "
                       f"`{f.location}` | {status} |")
        if len(new) > 50:
            out.append(f"\n…and {len(new) - 50} more in the full report.")
    else:
        out.append("\nNo new findings in this change. 👍")

    if run.diff.fixed:
        out.append(f"\n### Fixed 🎉 ({len(run.diff.fixed)})\n")
        out += [f"- `{f.rule_id}` {f.title}" + (f" (`{f.file}:{f.line}`)" if f.file else "") for f in run.diff.fixed[:30]]

    prompt_targets = [f for f in new if f.fix_prompt][:n_prompts]
    if prompt_targets:
        out.append("\n### 🤖 AI fix prompts\n")
        out.append("Copy a prompt into Claude, Cursor, Copilot, ChatGPT or any AI coding tool. "
                   "Code in prompts is redacted and capped at 40 lines.\n")
        for f in prompt_targets:
            out.append(_details(f"Fix prompt: <code>{f.rule_id}</code> at <code>{f.location}</code>",
                                _prompt_block(f.fix_prompt or "")))
        left = len([f for f in new if f.fix_prompt]) - len(prompt_targets)
        if left > 0:
            out.append(f"_{left} more prompt(s) are in the job summary and the HTML report._\n")
        if include_fix_all and run.fix_all_new_prompt:
            out.append(_details("<b>Fix all new findings</b> (one prompt)", _prompt_block(run.fix_all_new_prompt)))

    if run.head.suppressions or run.head.disabled_rules:
        rows = []
        for s in run.head.suppressions:
            rows.append(f"| `{s['file']}:{s['line']}` | {', '.join(s['rule_ids'])} | {s['reason'] or '—'} | "
                        f"{s['expires'] or '—'} | {s['state']} |")
        body = ""
        if rows:
            body += "| Where | Rules | Reason | Expires | State |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
        if run.head.disabled_rules:
            body += "**Rules turned off by config**\n\n" + "\n".join(
                f"- `{d['rule_id']}` {d['title']}: {d['reason']}" for d in run.head.disabled_rules)
        expired = sum(1 for s in run.head.suppressions if s["state"] == "expired")
        label = f"Suppressions ({len(run.head.suppressions)}) and disabled rules ({len(run.head.disabled_rules)})"
        if expired:
            label += f" · ⚠️ {expired} expired"
        out.append(_details(label, body.strip()))

    if g.notes:
        out.append("")
        out += [f"> {n}" for n in g.notes]
    links = []
    if report_url:
        links.append(f"[Full report]({report_url})")
    if rep.context.run_url:
        links.append(f"[Workflow run]({rep.context.run_url})")
    if links:
        out.append("\n" + " · ".join(links))
    out.append(f"\n<sub>{PROMPT_DISCLAIMER} Pass/fail comes from deterministic rules only. PrivTrace {__version__}.</sub>")
    return "\n".join(out).strip() + "\n"
