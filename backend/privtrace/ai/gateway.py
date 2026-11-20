"""The ONLY path from PrivTrace to Gemini.

Guarantees, enforced here and tested in tests/test_ai.py:
- Every prompt is redacted (Aadhaar, PAN, email, phone, cards, secrets, ...).
- Code is sent as snippets of at most `max_lines` lines around a finding, never whole files.
- Responses are validated against Pydantic schemas; invalid responses are dropped.
- AI output is attached as `AIEnrichment` (no status field) and cannot change a rule result.
- Any failure (no key, network, quota, bad JSON) degrades gracefully: the scan completes.
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import BaseModel, ValidationError

from privtrace.ai import prompts
from privtrace.ai.client import GeminiTransport, Transport
from privtrace.ai.schemas import AIClassificationNote, ClassificationResponse, FindingExplanation
from privtrace.core.config import Settings, get_settings
from privtrace.core.redaction import contains_unredacted_pii, redact
from privtrace.models.enums import RuleStatus
from privtrace.models.results import AIEnrichment, RuleResult
from privtrace.packs.schema import Pack
from privtrace.scanner.facts import CodeFacts

log = logging.getLogger("privtrace.ai")

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class UnsafePayloadError(RuntimeError):
    pass


class AIGateway:
    def __init__(self, transport: Transport, *, max_lines: int = 40, max_calls: int = 10):
        self.transport = transport
        self.max_lines = max_lines
        self.max_calls = max_calls
        self.calls = 0
        self.errors = 0

    # ---------------- safety choke point ----------------
    def guard(self, prompt: str) -> str:
        safe = redact(prompt)
        if contains_unredacted_pii(safe):  # redaction must be a fixed point
            raise UnsafePayloadError("prompt still contains identifiers after redaction")
        return safe

    def _send(self, prompt: str, schema: type[BaseModel]) -> BaseModel | None:
        if self.calls >= self.max_calls:
            return None
        self.calls += 1
        try:
            raw = self.transport.generate_json(self.guard(prompt), schema)
            return schema.model_validate_json(raw)
        except (ValidationError, ValueError) as e:
            self.errors += 1
            log.warning("AI response rejected (%s)", type(e).__name__)
        except Exception as e:  # network, quota, auth...
            self.errors += 1
            log.warning("AI call failed (%s); continuing without AI output", type(e).__name__)
        return None

    def snippet(self, root: Path, rel: str, line: int) -> str:
        """≤ max_lines lines around `line`, redacted. Never a whole file unless it is that short."""
        try:
            lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        half = self.max_lines // 2
        start = max(0, line - 1 - half)
        chunk = lines[start : start + self.max_lines]
        return redact("\n".join(chunk))

    # ---------------- (a) classify ambiguous fields ----------------
    def classify(self, facts: CodeFacts, root: Path, limit: int = 25) -> list[AIClassificationNote]:
        seen: dict[str, tuple[str, int, str]] = {}
        for m in facts.models:
            for f in m.ambiguous_fields:
                seen.setdefault(f, (m.file, m.line, f"field of model {m.name}"))
        for loc in facts.ambiguous_names:
            name = loc.snippet.split("=")[0].strip().split(" ")[-1] if "=" in loc.snippet else None
            if name and name.isidentifier():
                seen.setdefault(name, (loc.file, loc.line, loc.snippet[:160]))
        if not seen:
            return []
        items = list(seen.items())[:limit]
        text = "\n".join(f"- {n}  ({file}:{line}) context: {ctx}" for n, (file, line, ctx) in items)
        resp = self._send(prompts.CLASSIFY.format(items=text), ClassificationResponse)
        if not isinstance(resp, ClassificationResponse):
            return []
        notes = []
        for it in resp.items:
            if it.is_personal_data and it.name in seen and it.category not in ("none", ""):
                file, line, _ = seen[it.name]
                notes.append(AIClassificationNote(name=it.name, category=it.category, reason=it.reason, file=file, line=line))
        return notes

    # ---------------- (b) explain + (c) suggest fixes ----------------
    def explain(self, result: RuleResult, framework: str, root: Path) -> AIEnrichment | None:
        ev = result.evidence[0] if result.evidence else None
        snippet = self.snippet(root, ev.file, ev.line) if ev else ""
        prompt = prompts.EXPLAIN.format(
            title=result.title, framework=framework, reference=result.reference, message=result.message,
            location=f"{ev.file}:{ev.line}" if ev else "n/a", snippet=snippet or "(no code location)",
            fix_instruction=prompts.FIX_TEXT_ONLY if result.fix_diff else prompts.FIX_WITH_DIFF,
        )
        resp = self._send(prompt, FindingExplanation)
        if not isinstance(resp, FindingExplanation):
            return None
        return AIEnrichment(
            explanation=redact(resp.explanation),
            suggested_fix=redact(resp.suggested_fix) or None,
            suggested_diff=None if result.fix_diff else (redact(resp.suggested_diff) if resp.suggested_diff else None),
            model=getattr(self.transport, "model", None),
        )

    def enrich(self, results: list[RuleResult], packs: list[Pack], facts: CodeFacts, root: Path,
               max_explanations: int = 8) -> list[AIClassificationNote]:
        names = {p.id: p.short_name for p in packs}
        detector_of = {(p.id, r.id): r.detector or r.id for p in packs for r in p.rules}
        notes = self.classify(facts, root)
        candidates = sorted(
            (r for r in results if r.status in (RuleStatus.failed, RuleStatus.needs_review) and r.evidence),
            key=lambda r: (r.status != RuleStatus.failed, SEV_RANK[r.severity.value]),
        )
        done: dict[str, AIEnrichment | None] = {}
        for r in candidates:
            key = detector_of.get((r.pack_id, r.rule_id), r.rule_id)
            if key not in done:
                if len(done) >= max_explanations:
                    continue
                done[key] = self.explain(r, names.get(r.pack_id, r.pack_id), root)
            if done[key] is not None:
                r.ai = done[key]
        return notes


def gateway_from_settings(settings: Settings | None = None) -> AIGateway | None:
    s = settings or get_settings()
    if not s.gemini_configured:
        return None
    try:
        transport = GeminiTransport(api_key=s.gemini_api_key or "", model=s.gemini_model or "")
    except Exception as e:  # SDK missing / bad config
        log.warning("Gemini unavailable (%s); scanning without AI", type(e).__name__)
        return None
    return AIGateway(transport, max_lines=s.max_snippet_lines)
