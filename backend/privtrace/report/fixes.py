"""Template-based fix suggestions as unified diffs.

Generated deterministically from the source (while the workspace still exists).
Gemini is only asked for a fix when no template applies (see ai/), and those are
labelled "AI-suggested". Every diff line is redacted before it leaves this module.
"""

from __future__ import annotations

import ast
import difflib
import re
from collections.abc import Callable
from pathlib import Path

from privtrace.core.redaction import redact
from privtrace.models.enums import RuleStatus
from privtrace.models.results import Evidence, RuleResult
from privtrace.packs.schema import Pack
from privtrace.scanner.facts import CodeFacts, SinkKind

MAX_FILES_PER_FIX = 4
HELPER_NOTE = {
    "redact_pii": "# Note: uses a redact_pii() helper that masks Aadhaar/PAN/phone/email before data leaves the process.",
    "hash_password": "# Note: uses hash_password() backed by bcrypt/argon2 (e.g. passlib CryptContext).",
}


class SourceFile:
    """Mutable view of one file: apply offset-based edits, then diff."""

    def __init__(self, root: Path, rel: str):
        self.rel = rel
        self.text = (root / rel).read_text(encoding="utf-8", errors="replace")
        self.original = self.text
        self._lines = self.text.splitlines(keepends=True)
        self._edits: list[tuple[int, int, str]] = []
        try:
            self.tree: ast.Module | None = ast.parse(self.text)
        except SyntaxError:
            self.tree = None

    def offset(self, line: int, col: int) -> int:
        # ast col offsets are UTF-8 byte offsets
        prefix = sum(len(x) for x in self._lines[: line - 1])
        return prefix + len(self._lines[line - 1].encode("utf-8")[:col].decode("utf-8", errors="ignore"))

    def node_span(self, n: ast.AST) -> tuple[int, int]:
        return self.offset(n.lineno, n.col_offset), self.offset(n.end_lineno, n.end_col_offset)

    def replace(self, start: int, end: int, new: str) -> None:
        if any(not (end <= s or start >= e) for s, e, _ in self._edits):
            return  # overlapping edit; keep the first
        self._edits.append((start, end, new))

    def wrap(self, n: ast.AST, func: str) -> None:
        s, e = self.node_span(n)
        self.replace(s, e, f"{func}({self.text[s:e]})")

    def line_sub(self, line: int, pattern: str, repl: str) -> bool:
        if not 0 < line <= len(self._lines):
            return False
        old = self._lines[line - 1]
        new = re.sub(pattern, repl, old)
        if new == old:
            return False
        start = self.offset(line, 0)
        self.replace(start, start + len(old), new)
        return True

    def insert_after_line(self, line: int, block: str) -> None:
        pos = self.offset(line, 0) + len(self._lines[line - 1])
        if not self._lines[line - 1].endswith("\n"):
            block = "\n" + block
        self.replace(pos, pos, block)

    def calls_at(self, line: int) -> list[ast.Call]:
        if not self.tree:
            return []
        return [n for n in ast.walk(self.tree) if isinstance(n, ast.Call) and n.lineno <= line <= (n.end_lineno or n.lineno)
                and n.lineno == line]

    def diff(self) -> str | None:
        if not self._edits:
            return None
        text = self.text
        for s, e, new in sorted(self._edits, reverse=True):
            text = text[:s] + new + text[e:]
        d = difflib.unified_diff(
            self.original.splitlines(keepends=True), text.splitlines(keepends=True),
            fromfile=f"a/{self.rel}", tofile=f"b/{self.rel}", n=2,
        )
        out = "".join(d)
        return out or None


def _func_name(call: ast.Call) -> str:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _receiver_src(sf: SourceFile, call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute):
        s, e = sf.node_span(call.func.value)
        return sf.text[s:e]
    return None


# --------------------------------------------------------------------------
# Per-detector transforms: (SourceFile, Evidence, CodeFacts) -> notes used
# --------------------------------------------------------------------------
_CONTENT_KW = {"contents", "messages", "input", "prompt", "documents", "texts", "text", "content", "json", "data", "params", "msg"}
_SKIP_KW = {"model", "temperature", "max_tokens", "config", "timeout", "ex", "px", "ids", "headers", "verify", "embedding", "embeddings"}


def _wrap_sink_args(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    calls = sf.calls_at(ev.line)
    api_last = ev.detail.split("→")[-1].strip().split(" ")[0].rsplit(".", 1)[-1] if "→" in ev.detail else ""
    target = next((c for c in calls if _func_name(c) == api_last), calls[0] if calls else None)
    if target is None:
        return set()
    wrapped = False
    for kw in target.keywords:
        if kw.arg in _CONTENT_KW and kw.arg not in _SKIP_KW:
            sf.wrap(kw.value, "redact_pii")
            wrapped = True
    if not wrapped:
        args = target.args
        if _func_name(target) in ("debug", "info", "warning", "warn", "error", "exception", "critical", "log", "print"):
            # format string + args: wrap args; f-string message: wrap the message
            dyn = [a for a in args if not isinstance(a, ast.Constant)]
            for a in dyn:
                sf.wrap(a, "redact_pii")
                wrapped = True
        else:
            for a in args:
                if not isinstance(a, ast.Constant):
                    sf.wrap(a, "redact_pii")
                    wrapped = True
    return {"redact_pii"} if wrapped else set()


def _cache_ttl(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    for c in sf.calls_at(ev.line):
        if _func_name(c) == "set" and not any(k.arg in ("ex", "px", "exat", "pxat", "keepttl") for k in c.keywords):
            end = sf.offset(c.end_lineno, c.end_col_offset) - 1  # before ')'
            sf.replace(end, end, ", ex=CACHE_TTL_SECONDS")
            return {"ttl"}
    return set()


def _debug(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    if sf.rel.rsplit("/", 1)[-1].lower().startswith(".env") or sf.rel.endswith((".yml", ".yaml", ".ini", ".toml", ".cfg")):
        sf.line_sub(ev.line, r"(?i)(=|:\s*)['\"]?(true|1|yes|on)['\"]?", r"\1false")
    else:
        sf.line_sub(ev.line, r"debug\s*=\s*True", 'debug=os.getenv("APP_DEBUG") == "1"') or \
            sf.line_sub(ev.line, r"^(\s*\w*DEBUG\w*\s*=\s*)True", r'\1os.getenv("APP_DEBUG") == "1"')
    return set()


def _cors(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    sf.line_sub(ev.line, r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
                'allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(",")')
    return set()


def _secret(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    if sf.rel.endswith(".py"):
        sf.line_sub(ev.line, r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]).*?\3\s*$", r'\1\2 = os.environ["\2"]\n')
    return set()


def _transport(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    sf.line_sub(ev.line, r"verify\s*=\s*False", "verify=True") or sf.line_sub(ev.line, r"(['\"])http://", r"\1https://")
    return set()


def _passwords(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    if not sf.tree:
        return set()
    for n in ast.walk(sf.tree):
        if isinstance(n, ast.keyword) and n.arg and re.fullmatch(r"(password|passwd|pwd)", n.arg, re.I) and n.value.lineno == ev.line:
            if not re.search(r"hash", ast.unparse(n.value), re.I):
                sf.wrap(n.value, "hash_password")
                return {"hash_password"}
    return set()


def _erasure(sf: SourceFile, ev: Evidence, facts: CodeFacts) -> set[str]:
    """Append deletes for missing stores to the end of the delete handler."""
    if not sf.tree or "delete handler" not in ev.detail:
        return set()
    fn = next((n for n in ast.walk(sf.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno == ev.line), None)
    if fn is None:
        return set()
    info = next((f for f in facts.functions if f.file == sf.rel and f.line == fn.lineno), None)
    stores = {s.kind for s in facts.sinks if s.carries_pii and s.kind in (SinkKind.cache, SinkKind.vector_store, SinkKind.file_write, SinkKind.db_write)}
    missing = stores - (info.deletes if info else set())
    if not missing:
        return set()
    params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
    uid = next((p for p in params if "id" in p.lower()), params[0] if params else "user_id")
    last = fn.body[-1]
    indent = " " * last.col_offset
    lines = [f"{indent}# PrivTrace: erase this user's data from every store that holds it (adjust keys/filters)."]
    for kind in sorted(missing):
        sink = next((s for s in facts.sinks if s.kind == kind and s.carries_pii), None)
        recv = None
        if sink and sink.location.file == sf.rel:
            c = next(iter(sf.calls_at(sink.location.line)), None)
            recv = _receiver_src(sf, c) if c else None
        if kind == SinkKind.cache:
            prefix = (sink.store if sink and sink.store else "user")
            lines.append(f'{indent}{recv or "redis_client"}.delete(f"{prefix}:{{{uid}}}")')
        elif kind == SinkKind.vector_store:
            table = sink.store if sink and sink.store else None
            if table and recv in (None, "db", "session", "conn", "cur", "cursor") or (sink and "execute" in sink.api):
                lines.append(f'{indent}{recv or "db"}.execute(text("DELETE FROM {table or "embeddings"} WHERE user_id = :uid"), {{"uid": {uid}}})')
            else:
                lines.append(f'{indent}{recv or "collection"}.delete(where={{"user_id": {uid}}})')
        elif kind == SinkKind.file_write:
            lines.append(f"{indent}delete_user_files({uid})  # remove exports/uploads written for this user")
        elif kind == SinkKind.db_write:
            lines.append(f'{indent}db.execute(text("DELETE FROM users WHERE id = :uid"), {{"uid": {uid}}})')
    sf.insert_after_line(last.end_lineno, "\n".join(lines) + "\n")
    return set()


TRANSFORMS: dict[str, Callable[[SourceFile, Evidence, CodeFacts], set[str]]] = {
    "pii_to_llm_unredacted": _wrap_sink_args,
    "pii_in_logs": _wrap_sink_args,
    "pii_to_vector_store_unredacted": _wrap_sink_args,
    "cache_pii_without_ttl": _cache_ttl,
    "debug_mode_enabled": _debug,
    "cors_wildcard": _cors,
    "hardcoded_secrets": _secret,
    "insecure_transport": _transport,
    "plaintext_passwords": _passwords,
    "erasure_covers_all_stores": _erasure,
}


def generate_fixes(results: list[RuleResult], packs: list[Pack], facts: CodeFacts, root: Path) -> None:
    """Attach `fix_diff` to failed / needs-review results where a template applies."""
    detector_of = {(p.id, r.id): r.detector for p in packs for r in p.rules}
    cache: dict[str, str | None] = {}
    for res in results:
        if res.status not in (RuleStatus.failed, RuleStatus.needs_review):
            continue
        det = detector_of.get((res.pack_id, res.rule_id))
        if det not in TRANSFORMS:
            continue
        if det in cache:
            res.fix_diff = cache[det]
            continue
        files: dict[str, SourceFile] = {}
        notes: set[str] = set()
        for ev in res.evidence:
            if ev.file not in files:
                if len(files) >= MAX_FILES_PER_FIX:
                    continue
                try:
                    files[ev.file] = SourceFile(root, ev.file)
                except OSError:
                    continue
            try:
                notes |= TRANSFORMS[det](files[ev.file], ev, facts)
            except Exception:  # a template must never break the scan
                continue
        diffs = [d for sf in files.values() if (d := sf.diff())]
        text = None
        if diffs:
            header = "\n".join(HELPER_NOTE[n] for n in sorted(notes) if n in HELPER_NOTE)
            text = redact((header + "\n" if header else "") + "".join(diffs))
        cache[det] = text
        res.fix_diff = text
