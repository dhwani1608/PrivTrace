"""Copy-paste AI fix prompts, generated deterministically from Jinja2 templates.

No LLM call happens here, so prompts work offline and in CI. Guarantees (tested in
tests/test_fix_prompts.py):

- Code context is redacted and capped (`max_lines` lines per prompt block).
- Repository code is fenced with a fence longer than any backtick run inside it and labelled as
  data, not instructions (prompt-injection guard).
- The rendered prompt passes through `redact()` once more before it is returned.
- Plain, tool-agnostic Markdown.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from privtrace.core.redaction import redact
from privtrace.findings import Finding, SourceCache, language_of
from privtrace.fixprompt.criteria import CONSTRAINTS, CRITERIA
from privtrace.models.enums import CheckType, RuleStatus
from privtrace.models.results import RuleResult
from privtrace.packs.schema import Pack, PackRule
from privtrace.scanner.facts import STORAGE_SINKS, CodeFacts

TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(TEMPLATES), autoescape=False, trim_blocks=True, lstrip_blocks=True,
    keep_trailing_newline=True, undefined=StrictUndefined,
)

PROMPT_DISCLAIMER = (
    "PrivTrace findings are engineering evidence from automated code analysis, not legal advice "
    "and not a legal determination about any law. Have a qualified professional review your obligations."
)
MAX_LOCATIONS = 5          # per-rule prompt: locations shown in full
MAX_DIFF_LINES = 40        # template diff included only if it is this short
DEFAULT_TOP = 10
DEFAULT_MAX_CHARS = 30_000
# Checks whose evidence points at a function definition: show the function, not a window.
FUNCTION_LEVEL = {"erasure_covers_all_stores", "delete_endpoints_authenticated", "consent_captured_at_collection"}
_BACKTICKS = re.compile(r"`+")


def _fence(text: str) -> str:
    longest = max((len(m.group(0)) for m in _BACKTICKS.finditer(text)), default=0)
    return "`" * max(3, longest + 1)


def _finalise(text: str) -> str:
    text = redact(text)  # belt and braces: every input is already redacted
    text = re.sub(r"[ \t]+\n", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


Pair = tuple[RuleResult, Finding]


class PromptBuilder:
    def __init__(self, packs: Sequence[Pack], facts: CodeFacts | None, src: SourceCache,
                 pack_ids: Sequence[str], *, max_lines: int = 40, verify_cmd: str | None = None):
        self.facts = facts
        self.src = src
        self.max_lines = max(10, max_lines)
        self.packs = {p.id: p for p in packs}
        self.rules: dict[tuple[str, str], PackRule] = {(p.id, r.id): r for p in packs for r in p.rules}
        self.verify_cmd = verify_cmd or f"privtrace scan . --packs {','.join(pack_ids)}"

    # ------------------------------------------------------------------ helpers
    def _detector(self, r: RuleResult) -> str:
        rule = self.rules.get((r.pack_id, r.rule_id))
        return (rule.detector if rule and rule.detector else "") or ""

    def _rule_meta(self, r: RuleResult) -> dict[str, Any]:
        pack = self.packs.get(r.pack_id)
        return {
            "rule_id": r.rule_id, "title": r.title, "severity": r.severity.value, "status": r.status.value,
            "framework": pack.short_name if pack else r.pack_id, "reference": r.reference,
            "reference_verified": r.reference_verified, "source_url": r.source_url,
        }

    def _blocks(self, findings: Sequence[Finding], detector: str) -> list[dict[str, Any]]:
        located = [f for f in findings if f.file and f.line and self.src.lines(f.file)]
        if not located:
            return []
        per = max(5, self.max_lines // len(located))
        windows: list[tuple[str, int, int, set[int]]] = []
        for f in located:
            span = self.src.function_span(f.file, f.line) if detector in FUNCTION_LEVEL else None
            if span:
                start, end = span[0], min(span[1], span[0] + self.max_lines - 1)
            else:
                before = (per - 1) // 2
                start, end = max(1, f.line - before), f.line + (per - 1 - before)
            windows.append((f.file, start, end, {f.line}))
        # merge overlapping windows in the same file
        windows.sort(key=lambda w: (w[0], w[1]))
        merged: list[tuple[str, int, int, set[int]]] = []
        for w in windows:
            if merged and merged[-1][0] == w[0] and w[1] <= merged[-1][2] + 1:
                f0, s0, e0, h0 = merged[-1]
                merged[-1] = (f0, s0, max(e0, w[2]), h0 | w[3])
            else:
                merged.append(w)
        blocks: list[dict[str, Any]] = []
        budget = self.max_lines
        for file, start, end, hits in merged:
            if budget <= 0:
                break
            end = min(end, start + budget - 1)
            first, lines = self.src.window(file, start, 0, end - start)
            if not lines:
                continue
            last = first + len(lines) - 1
            budget -= len(lines)
            width = len(str(last))
            body = "\n".join(
                f"{'>' if first + i in hits else ' '} {str(first + i).rjust(width)} | {text}"
                for i, text in enumerate(lines)
            )
            blocks.append({"file": file, "start": first, "end": last, "lang": language_of(file),
                           "body": body, "fence": _fence(body)})
        return blocks

    def _flows(self, findings: Sequence[Finding], detector: str) -> tuple[list[str], list[str]]:
        """(flow sentences, stores for erasure checklists)."""
        facts = self.facts
        if facts is None:
            return [], []
        routes = {(fn.file, fn.qualname): fn for fn in facts.functions}
        merged: dict[tuple, tuple[set[str], set[str]]] = {}
        for f in findings:
            for s in facts.sinks:
                if s.location.file != f.file or s.location.line != f.line or not s.carries_pii:
                    continue
                fn = routes.get((s.location.file, s.function))
                origin = f"`{fn.route_method} {fn.route_path}` (handler `{s.function}`)" if fn and fn.route_path                     else f"`{s.function}`"
                key = (origin, s.api, s.location.file, s.location.line, s.store,
                       tuple(f"{v.file}:{v.line}" for v in s.via[:3]))
                names, cats = merged.setdefault(key, (set(), set()))
                names.update(t.name for t in s.taints)
                cats.update(t.category for t in s.taints)
        flows: list[str] = []
        for (origin, api, file, line, store, via), (names, cats) in merged.items():
            shown = sorted(names)[:6]
            text = (f"Personal data {', '.join(f'`{n}`' for n in shown)} ({', '.join(sorted(cats))}) flows from "
                    f"{origin} → `{api}` at `{file}:{line}`")
            if store:
                text += f" (store: `{store}`)"
            if via:
                text += "; reached via " + ", ".join(f"`{v}`" for v in via)
            flows.append(text)
        stores: list[str] = []
        if detector in ("erasure_covers_all_stores", "retention_mechanism_present", "cache_pii_without_ttl"):
            seen: set[tuple[str, str]] = set()
            for s in facts.sinks:
                if s.kind not in STORAGE_SINKS or not s.carries_pii:
                    continue
                key = (s.kind.value, s.store or s.api)
                if key in seen:
                    continue
                seen.add(key)
                stores.append(f"{s.kind.value}: `{s.store or s.api}` (written at `{s.location.file}:{s.location.line}`)")
            if stores and detector == "erasure_covers_all_stores":
                flows.append("Personal data is stored in: " + "; ".join(stores))
                for f in findings:
                    h = next((x for x in facts.functions if x.file == f.file and x.line == f.line), None)
                    if h is not None:
                        done = ", ".join(sorted(k.value for k in h.deletes)) or "nothing"
                        flows.append(f"The delete handler `{h.qualname}` currently erases: {done}.")
        return list(dict.fromkeys(flows)), stores

    def _item(self, rules: Sequence[RuleResult], findings: Sequence[Finding], *,
              max_locations: int = MAX_LOCATIONS) -> dict[str, Any]:
        lead = rules[0]
        detector = self._detector(lead)
        shown = list(findings)[:max_locations]
        flows, stores = self._flows(shown, detector)
        hints: list[str] = []
        for r in rules:
            rule = self.rules.get((r.pack_id, r.rule_id))
            hints.extend(rule.fix_prompt_hints if rule else [])
        criteria = list(CRITERIA.get(detector, []))
        if lead.check_type != CheckType.automated and lead.question:
            criteria.append(
                f"Checklist question for this rule: \"{lead.question}\" Once the answer is genuinely 'yes', "
                f"record it in `.privtrace.yml` under `manual_answers: {{{lead.rule_id}: yes}}`."
            )
        diff = next((r.fix_diff for r in rules if r.fix_diff), None)
        if diff and len(diff.splitlines()) > MAX_DIFF_LINES:
            diff = None
        ai = next((r.ai.suggested_fix for r in rules if r.ai and r.ai.suggested_fix), None)
        ids = list(dict.fromkeys(r.rule_id for r in rules))
        tmpl = f"criteria/{detector}.md.j2"
        sev = max((r.severity for r in rules), key=lambda s: s.rank)
        return {
            "headline": lead.title if len(ids) == 1 else f"{lead.title} ({', '.join(ids)})",
            "rule_ids": ids,
            "severity": sev.value,
            "rules": [self._rule_meta(r) for r in _unique_rules(rules)],
            "why": lead.why_it_matters,
            "message": lead.message,
            "remediation": lead.remediation,
            "locations": [{"file": f.file, "line": f.line, "function": f.function, "detail": f.detail}
                          for f in shown if f.file],
            "more_locations": max(0, len([f for f in findings if f.file]) - len(shown)),
            "blocks": self._blocks(shown, detector),
            "flows": flows,
            "stores": stores,
            "criteria": criteria,
            "hints": list(dict.fromkeys(hints)),
            "template_diff": diff.rstrip("\n") if diff else None,
            "template_diff_fence": _fence(diff or ""),
            "ai_guidance": ai,
            "criteria_template": tmpl if (TEMPLATES / tmpl).exists() else "criteria/_generic.md.j2",
        }

    def _common(self) -> dict[str, Any]:
        return {"constraints": CONSTRAINTS, "verify_cmd": self.verify_cmd, "disclaimer": PROMPT_DISCLAIMER}

    # ------------------------------------------------------------------ prompts
    def rule_prompt(self, r: RuleResult, findings: Sequence[Finding]) -> str:
        item = self._item([r], findings)
        return _finalise(_env.get_template("single.md.j2").render(item=item, **self._common()))

    def file_prompt(self, file: str, pairs: Sequence[Pair]) -> str:
        items = [self._item(rs, fs) for rs, fs in _group(pairs)]
        ids = list(dict.fromkeys(i for it in items for i in it["rule_ids"]))
        return _finalise(_env.get_template("file.md.j2").render(file=file, items=items, rule_ids=ids, **self._common()))

    def batch_prompt(self, pairs: Sequence[Pair], *, top: int = DEFAULT_TOP,
                     max_chars: int = DEFAULT_MAX_CHARS) -> str | None:
        groups = _group(pairs)
        if not groups:
            return None
        total = len(groups)
        n = max(1, min(top, total))
        while True:
            chosen = groups[:n]
            text = self._render_batch(chosen, total)
            if len(text) <= max_chars or n == 1:
                return text
            n -= 1

    def _render_batch(self, chosen: list[tuple[list[RuleResult], list[Finding]]], total: int) -> str:
        items = []
        for order, (rs, fs) in enumerate(chosen, 1):
            it = self._item(rs, fs, max_locations=3)
            it["order"] = order
            items.append(it)
        by_file: dict[str, list[dict[str, Any]]] = {}
        for it in items:
            by_file.setdefault(it["locations"][0]["file"] if it["locations"] else "", []).append(it)
        file_groups = [{"file": f, "entries": its} for f, its in by_file.items()]
        omitted = total - len(chosen)
        ids = list(dict.fromkeys(i for it in items for i in it["rule_ids"]))
        return _finalise(_env.get_template("batch.md.j2").render(
            items=items, groups=file_groups, omitted=omitted, rule_ids=ids,
            omitted_reason="this prompt is capped to keep it small enough for an AI coding tool",
            **self._common(),
        ))


def _unique_rules(rules: Iterable[RuleResult]) -> list[RuleResult]:
    seen: set[tuple[str, str]] = set()
    out = []
    for r in rules:
        if (r.pack_id, r.rule_id) not in seen:
            seen.add((r.pack_id, r.rule_id))
            out.append(r)
    return out


def _group(pairs: Sequence[Pair]) -> list[tuple[list[RuleResult], list[Finding]]]:
    """Merge findings in one file from rules that share a check (e.g. DPDP-SEC-02 and SECB-LOG-01
    on the same log lines) so the AI makes one coherent edit, not several conflicting ones."""
    groups: dict[tuple[str, str], tuple[list[RuleResult], list[Finding]]] = {}
    for r, f in pairs:
        key = (f.file, _check_key(r) if f.file else r.rule_id)
        rs, fs = groups.setdefault(key, ([], []))
        if r not in rs:
            rs.append(r)
        if not any(x.file == f.file and x.line == f.line for x in fs):
            fs.append(f)
    ordered = sorted(
        groups.values(),
        key=lambda g: (
            all(r.status != RuleStatus.failed for r in g[0]),
            -max(r.severity.rank for r in g[0]),
            g[1][0].file == "", g[1][0].file, g[1][0].line,
        ),
    )
    for _rs, fs in ordered:
        fs.sort(key=lambda f: f.line)
    return ordered


def _check_key(r: RuleResult) -> str:
    # The message is produced by the shared check, so equal messages == same detector output.
    return r.message


def attach_prompts(results: list[RuleResult], findings: list[Finding], builder: PromptBuilder,
                   *, top: int = DEFAULT_TOP) -> tuple[dict[str, str], str | None]:
    """Fill `RuleResult.fix_prompt` / `Finding.fix_prompt`; return (file prompts, fix-all prompt)."""
    by_rule: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        by_rule.setdefault((f.pack_id, f.rule_id), []).append(f)
    pairs: list[Pair] = []
    for r in results:
        fs = by_rule.get((r.pack_id, r.rule_id))
        if not fs:
            continue
        r.fix_prompt = builder.rule_prompt(r, fs)
        r.fix_prompt_ai_enriched = bool(r.ai and r.ai.suggested_fix)
        for f in fs:
            f.fix_prompt = r.fix_prompt if len(fs) == 1 else builder.rule_prompt(r, [f])
            pairs.append((r, f))
    file_prompts: dict[str, str] = {}
    files = sorted({f.file for _, f in pairs if f.file})
    for file in files:
        file_prompts[file] = builder.file_prompt(file, [p for p in pairs if p[1].file == file])
    return file_prompts, builder.batch_prompt(pairs, top=top)
