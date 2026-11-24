"""Per-location findings with stable fingerprints.

A `RuleResult` is one rule with up to 25 evidence locations. CI needs to know whether *this* log
leak is new or was already there, so every failed / needs-review rule is flattened into one
`Finding` per evidence location (or a single location-less finding for rules without evidence,
e.g. unanswered checklist questions).

Fingerprint (see docs/CI_INTEGRATION.md#fingerprints):

    sha256(rule_id | file | enclosing function | sha256(normalised redacted line) | occurrence)[:16]

- the enclosing function (innermost def/class qualname) keeps it stable when lines are inserted above;
- the line is hashed *after* redaction, so a fingerprint can never be brute-forced back to an
  identifier such as an Aadhaar or phone number;
- `privtrace-ignore` comments are stripped before hashing, so adding a suppression does not change
  the identity of the finding it suppresses;
- `occurrence` separates identical lines in the same function.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from privtrace.core.redaction import redact
from privtrace.models.enums import RuleStatus
from privtrace.models.results import Finding, RuleResult

MODULE = "<module>"
_SUPPRESS_COMMENT = re.compile(r"#\s*privtrace-ignore\b.*$")
_WS = re.compile(r"\s+")

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript", ".tsx": "tsx",
    ".java": "java", ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".kt": "kotlin",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml", ".ini": "ini", ".cfg": "ini",
    ".sql": "sql", ".sh": "bash", ".md": "markdown", ".html": "html", ".tf": "hcl",
}


def language_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if name.startswith(".env"):
        return "dotenv"
    if name == "dockerfile":
        return "dockerfile"
    return LANGUAGES.get(Path(name).suffix, "text")


class SourceCache:
    """Reads repo files once; answers 'which function is line N in' and 'lines around N'."""

    def __init__(self, root: Path | None):
        self.root = root
        self._lines: dict[str, list[str] | None] = {}
        self._spans: dict[str, list[tuple[int, int, str]]] = {}

    def lines(self, rel: str) -> list[str] | None:
        if rel not in self._lines:
            text = None
            if self.root is not None and rel:
                try:
                    text = (self.root / rel).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = None
            self._lines[rel] = text.splitlines() if text is not None else None
        return self._lines[rel]

    def line(self, rel: str, n: int) -> str:
        ls = self.lines(rel)
        if not ls or not 0 < n <= len(ls):
            return ""
        return ls[n - 1]

    def _function_spans(self, rel: str) -> list[tuple[int, int, str]]:
        if rel in self._spans:
            return self._spans[rel]
        spans: list[tuple[int, int, str]] = []
        ls = self.lines(rel)
        if ls is not None and rel.endswith(".py"):
            try:
                tree = ast.parse("\n".join(ls))
            except SyntaxError:
                tree = None
            if tree is not None:
                def walk(node: ast.AST, prefix: str) -> None:
                    for child in ast.iter_child_nodes(node):
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            q = f"{prefix}.{child.name}" if prefix else child.name
                            start = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                            spans.append((start, child.end_lineno or child.lineno, q))
                            walk(child, q)
                        else:
                            walk(child, prefix)
                walk(tree, "")
        self._spans[rel] = spans
        return spans

    def enclosing(self, rel: str, line: int) -> str:
        """Innermost def/class qualname containing `line` (`<module>` if none)."""
        best: tuple[int, str] | None = None
        for start, end, q in self._function_spans(rel):
            if start <= line <= end and (best is None or start >= best[0]):
                best = (start, q)
        return best[1] if best else MODULE

    def function_span(self, rel: str, line: int) -> tuple[int, int] | None:
        best: tuple[int, int] | None = None
        for start, end, _q in self._function_spans(rel):
            if start <= line <= end and (best is None or start >= best[0]):
                best = (start, end)
        return best

    def window(self, rel: str, line: int, before: int, after: int) -> tuple[int, list[str]]:
        """(first line number, redacted lines) around `line`."""
        ls = self.lines(rel)
        if not ls:
            return 0, []
        start = max(1, line - before)
        end = min(len(ls), max(line, 1) + after)
        return start, redact("\n".join(ls[start - 1 : end])).split("\n")


def normalise_code(line: str) -> str:
    """Redact, drop `privtrace-ignore` comments, collapse whitespace."""
    text = _SUPPRESS_COMMENT.sub("", redact(line))
    return _WS.sub(" ", text).strip()


def fingerprint(rule_id: str, file: str, function: str, code: str, occurrence: int = 0) -> str:
    code_hash = hashlib.sha256(normalise_code(code).encode("utf-8")).hexdigest()
    raw = "|".join([rule_id, file, function, code_hash, str(occurrence)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


ACTIONABLE = (RuleStatus.failed, RuleStatus.needs_review)


def extract_findings(results: list[RuleResult], src: SourceCache) -> list[Finding]:
    """Flatten failed / needs-review rule results into per-location findings."""
    findings: list[Finding] = []
    for r in results:
        if r.status not in ACTIONABLE:
            continue
        seen: dict[tuple[str, str, str], int] = {}
        locations = r.evidence or [None]
        for ev in locations:
            file = ev.file if ev else ""
            line = ev.line if ev else 0
            code = src.line(file, line) if file else ""
            if file and not code and ev is not None:
                code = ev.snippet  # file not on disk (e.g. loaded report): fall back to the stored snippet
            function = src.enclosing(file, line) if file else MODULE
            key = (file, function, normalise_code(code))
            occ = seen.get(key, 0)
            seen[key] = occ + 1
            fp = fingerprint(r.rule_id, file, function, code, occ)
            findings.append(Finding(
                id=fp[:10], fingerprint=fp, pack_id=r.pack_id, rule_id=r.rule_id, title=r.title,
                severity=r.severity, status=r.status, file=file, line=line, function=function,
                snippet=redact(ev.snippet if ev and ev.snippet else code.strip())[:300],
                detail=ev.detail if ev else r.message,
            ))
    findings.sort(key=lambda f: (f.status != RuleStatus.failed, -f.severity.rank, f.rule_id, f.file, f.line))
    return findings
