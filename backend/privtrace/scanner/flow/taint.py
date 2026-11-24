"""Simple taint analysis: which personal data reaches which sink.

Scope (documented in docs/DETECTION_LIMITS.md):
- Intra-function, flow-insensitive within loops (bodies run twice).
- Cross-function via *summaries*: for each function we record which parameters
  reach which sinks; call sites in the same file or imported repo modules
  (`from .llm import ask`) reuse those summaries. 3 rounds of propagation.
- Sources: PII-named variables/params/attributes/dict keys, parameters annotated
  with a PII model, raw request bodies, and PII model constructors.
- Sanitizers: calls whose name looks like redact/mask/hash/encrypt drop taint.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from privtrace.core.redaction import redact
from privtrace.scanner.detectors.pii_names import classify_name
from privtrace.scanner.facts import (
    ConfigFact,
    DeleteOp,
    Location,
    PiiModel,
    SinkEvent,
    SinkKind,
    Taint,
)
from privtrace.scanner.flow import sinks as S
from privtrace.scanner.parsers.base import ParsedModule

PARAM = "__param__"
KNOWN_KINDS = frozenset(S.FACTORIES.values()) | frozenset(S.DERIVED.values()) | {"file_w"}

Value = tuple[frozenset[Taint], bool]  # (taints, passed-through-sanitizer)
EMPTY: Value = (frozenset(), False)


def _union(*vals: Value) -> Value:
    t: set[Taint] = set()
    s = False
    for v in vals:
        t |= v[0]
        s = s or v[1]
    return frozenset(t), s


def _snippet(mod: ParsedModule, line: int) -> str:
    text = mod.line(line).strip()
    text = redact(text)
    return text if len(text) <= 200 else text[:200] + "…"


def loc(mod: ParsedModule, node: ast.AST) -> Location:
    line = getattr(node, "lineno", 0)
    return Location(file=mod.path, line=line, snippet=_snippet(mod, line))


def name_taint(name: str) -> frozenset[Taint]:
    c = classify_name(name)
    if c and c.is_pii:
        return frozenset({Taint(category=c.category, name=name)})
    return frozenset()


def literal_str(node: ast.AST | None) -> str | None:
    """Best-effort literal string: constants, f-strings (holes -> {}), text("...")."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    if isinstance(node, ast.Call) and node.args and isinstance(node.func, (ast.Name, ast.Attribute)):
        fname = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        if fname == "text":
            return literal_str(node.args[0])
    if isinstance(node, ast.BinOp):
        left, right = literal_str(node.left), literal_str(node.right)
        if left is not None or right is not None:
            return (left or "{}") + (right or "{}")
    return None


def is_dynamic_string(node: ast.AST) -> bool:
    """f-string with holes, '+' concatenation with a non-literal, '%' or .format()."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
        fname = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        if fname == "text" and node.args:
            return is_dynamic_string(node.args[0])
    return False


_NON_PII_ATTR = re.compile(r"^(id|pk|uuid|guid|\w+_id|\w+_at|created|updated|count|status|state|type|kind|version|is_\w+|has_\w+)$")
# Pydantic / dataclass-style serialisers that accept include= / exclude= field selections.
_SERIALISERS = frozenset({"model_dump", "model_dump_json", "dict", "json"})


def _field_names(node: ast.AST | None) -> set[str] | None:
    """{'a', 'b'} for literal sets / lists / tuples of strings or dict keys; None if not literal."""
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        elts = node.elts
    elif isinstance(node, ast.Dict):
        elts = [k for k in node.keys if k is not None]
    else:
        return None
    names = {e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return names if len(names) == len(elts) else None


def _apply_include_exclude(call: ast.Call, value: Value) -> Value:
    """`req.model_dump(exclude={"password"})` does not carry the password (and `include=` keeps only
    the listed fields). Only literal selections are trusted; anything dynamic keeps every taint."""
    taints, sanitized = value
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    exclude = _field_names(kw.get("exclude"))
    include = _field_names(kw.get("include"))

    def field(t: Taint) -> str:
        return t.name.rsplit(".", 1)[-1]

    if exclude:
        taints = frozenset(t for t in taints if field(t) not in exclude)
    if include is not None:
        taints = frozenset(t for t in taints if field(t) in include or t.category == PARAM)
    return (taints, sanitized)
_SQL_KEYWORD = re.compile(r"\b(select|insert|update|delete|where|from)\b", re.I)


# --------------------------------------------------------------------------
@dataclass
class FunctionRef:
    key: str
    mod: ParsedModule
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module
    qualname: str
    class_name: str | None = None

    @property
    def params(self) -> list[str]:
        if isinstance(self.node, ast.Module):
            return []
        a = self.node.args
        names = [p.arg for p in [*a.posonlyargs, *a.args]]
        if self.class_name and names and names[0] in ("self", "cls"):
            names = names[1:]
        return names + [p.arg for p in a.kwonlyargs]


@dataclass
class Summary:
    """Which params reach which sinks, and which store kinds a function deletes."""

    param_flows: dict[int, list[SinkEvent]] = field(default_factory=dict)
    deletes: set[SinkKind] = field(default_factory=set)


@dataclass
class Index:
    modules: dict[str, ParsedModule]                 # module name -> module
    models: dict[str, PiiModel]                      # class name -> model
    functions: dict[str, FunctionRef]                # key -> ref
    module_kinds: dict[str, dict[str, str]]          # module -> var -> kind
    class_kinds: dict[tuple[str, str], dict[str, str]]  # (module, class) -> "self.x" -> kind

    def find_module(self, dotted: str) -> ParsedModule | None:
        if dotted in self.modules:
            return self.modules[dotted]
        # scan roots vary (repo/app/...): accept a unique suffix match
        cands = [m for name, m in self.modules.items() if name.endswith("." + dotted) or dotted.endswith("." + name)]
        return cands[0] if len(cands) == 1 else None


class FunctionAnalyzer:
    def __init__(self, ref: FunctionRef, index: Index, summaries: dict[str, Summary]):
        self.ref = ref
        self.mod = ref.mod
        self.index = index
        self.summaries = summaries
        self.env: dict[str, Value] = {}
        self.kinds: dict[str, str] = dict(index.module_kinds.get(self.mod.module, {}))
        if ref.class_name:
            self.kinds.update(index.class_kinds.get((self.mod.module, ref.class_name), {}))
        self.sql_dyn_vars: set[str] = set()
        self.sinks: list[SinkEvent] = []
        self.deletes: list[DeleteOp] = []
        self.config: list[ConfigFact] = []
        self.calls: list[str] = []
        self.summary = Summary()
        self._seen: set[tuple] = set()

    # ---------------- entry ----------------
    def run(self) -> FunctionAnalyzer:
        node = self.ref.node
        if isinstance(node, ast.Module):
            body = [s for s in node.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        else:
            self._seed_params(node)
            body = node.body
        self._block(body)
        self._block(body)  # second pass picks up assignments that appear after use in loops
        # A cache key written and then `expire`d in the same function has a TTL.
        if any(d.kind == SinkKind.cache and d.api.endswith(("expire", "pexpire", "expireat")) for d in self.deletes):
            for s in self.sinks:
                if s.kind == SinkKind.cache and s.function == self.ref.qualname:
                    s.has_ttl = True
        return self

    def _seed_params(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        a = fn.args
        all_params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
        positional = [*a.posonlyargs, *a.args]
        first = positional[0] if positional else None
        idx = 0
        for p in all_params:
            if self.ref.class_name and p is first and p.arg in ("self", "cls"):
                continue
            taints: set[Taint] = set(name_taint(p.arg))
            taints.add(Taint(category=PARAM, name=str(idx)))
            ann = self._annotation_name(p.annotation)
            if ann:
                model = self.index.models.get(ann.split(".")[-1])
                if model and model.fields:
                    taints |= {Taint(category=f.category, name=f"{model.name}.{f.name}") for f in model.fields}
                kind = S.ANNOTATION_KINDS.get(ann) or S.ANNOTATION_KINDS.get(ann.split(".")[-1])
                self.kinds[p.arg] = kind or ""
            self.env[p.arg] = (frozenset(taints), False)
            idx += 1

    def _annotation_name(self, ann: ast.AST | None) -> str | None:
        if ann is None:
            return None
        if isinstance(ann, ast.Subscript):  # Optional[X], Annotated[X, ...], list[X]
            inner = ann.slice
            if isinstance(inner, ast.Tuple) and inner.elts:
                inner = inner.elts[0]
            return self._annotation_name(inner)
        if isinstance(ann, ast.BinOp):  # X | None
            return self._annotation_name(ann.left)
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            return ann.value
        chain = self.resolve(ann)
        return chain if chain != "?" else None

    # ---------------- resolution ----------------
    def resolve(self, e: ast.AST) -> str:
        if isinstance(e, ast.Name):
            if e.id in self.kinds:
                return self.kinds[e.id] or e.id
            if e.id in self.mod.imports:
                return self.mod.imports[e.id]
            return S.NAME_HINTS.get(e.id, e.id)
        if isinstance(e, ast.Attribute):
            if isinstance(e.value, ast.Name) and e.value.id == "self":
                k = self.kinds.get(f"self.{e.attr}")
                if k:
                    return k
                return S.NAME_HINTS.get(e.attr, f"self.{e.attr}")
            return f"{self.resolve(e.value)}.{e.attr}"
        if isinstance(e, ast.Call):
            f = self.resolve(e.func)
            if f in S.FACTORIES:
                return S.FACTORIES[f]
            if isinstance(e.func, ast.Attribute):
                recv = self.resolve(e.func.value)
                d = S.DERIVED.get((recv, e.func.attr))
                if d:
                    return d
            if (f, "__call__") in S.DERIVED:
                return S.DERIVED[(f, "__call__")]
            return f + "()"
        if isinstance(e, ast.Subscript):
            return self.resolve(e.value) + "[]"
        if isinstance(e, ast.Await):
            return self.resolve(e.value)
        return "?"

    def kind_of(self, e: ast.AST) -> str:
        if isinstance(e, ast.Await):
            e = e.value
        if isinstance(e, ast.Call):
            fname = self.resolve(e.func)
            if fname in ("open", "builtins.open", "io.open", "aiofiles.open"):
                mode = e.args[1] if len(e.args) > 1 else next((k.value for k in e.keywords if k.arg == "mode"), None)
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+"):
                    return "file_w"
            if fname in ("csv.writer", "csv.DictWriter"):
                return "file_w"
        r = self.resolve(e)
        return r if r in KNOWN_KINDS else ""

    # ---------------- taint evaluation ----------------
    def eval(self, e: ast.AST | None) -> Value:
        if e is None or isinstance(e, (ast.Constant, ast.Lambda, ast.Compare)):
            return EMPTY
        if isinstance(e, ast.Name):
            if e.id in self.env:
                return self.env[e.id]
            return (name_taint(e.id), False)
        if isinstance(e, ast.Attribute):
            if isinstance(e.value, ast.Name) and e.value.id == "self" and f"self.{e.attr}" in self.env:
                return self.env[f"self.{e.attr}"]
            base = self.eval(e.value)
            own = name_taint(e.attr)
            if own:
                params = frozenset(t for t in base[0] if t.category == PARAM)
                return (own | params, base[1])
            # `user.id` / `row.created_at` are keys and metadata, not the object's personal data.
            if _NON_PII_ATTR.match(e.attr):
                return (frozenset(t for t in base[0] if t.category == PARAM), base[1])
            # Other attributes of a model object don't carry every model field ("Model.field").
            return (frozenset(t for t in base[0] if "." not in t.name), base[1])
        if isinstance(e, ast.Subscript):
            key = e.slice
            base = self.eval(e.value)
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                own = name_taint(key.value)
                if own:
                    params = frozenset(t for t in base[0] if t.category == PARAM)
                    return (own | params, base[1])
            return base
        if isinstance(e, ast.Call):
            return self._eval_call(e)
        if isinstance(e, ast.Await):
            return self.eval(e.value)
        return _union(*(self.eval(c) for c in self._child_exprs(e)))

    def _child_exprs(self, e: ast.AST) -> list[ast.AST]:
        out: list[ast.AST] = []
        for c in ast.iter_child_nodes(e):
            if isinstance(c, ast.expr):
                out.append(c)
            elif isinstance(c, (ast.comprehension, ast.keyword)):
                out.extend(x for x in ast.iter_child_nodes(c) if isinstance(x, ast.expr))
        return out

    def _eval_call(self, call: ast.Call) -> Value:
        chain = self.resolve(call.func)
        last = chain.rsplit(".", 1)[-1]
        # `redact(x)`, `bcrypt.hashpw(...)`, `hashlib.sha256(x).hexdigest()`, `mask(x).strip()`
        if S.SANITIZER_NAME.search(last) or ("()" in chain and S.SANITIZER_NAME.search(chain.rsplit("()", 1)[0])):
            return (frozenset(), True)
        if S.REQUEST_BODY.search(chain):
            return (frozenset({Taint(category="request_body", name="request body")}), False)
        parts: list[Value] = [self.eval(a) for a in call.args]
        parts += [self.eval(k.value) for k in call.keywords]
        if isinstance(call.func, ast.Attribute):
            parts.append(self.eval(call.func.value))
        model = self.index.models.get(last)
        if model and model.fields:
            parts.append((frozenset(Taint(category=f.category, name=f"{model.name}.{f.name}") for f in model.fields), False))
        value = _union(*parts)
        if last in _SERIALISERS:
            value = _apply_include_exclude(call, value)
        return value

    # ---------------- statements ----------------
    def _block(self, stmts: list[ast.stmt]) -> None:
        for st in stmts:
            self._stmt(st)

    def _stmt(self, st: ast.stmt) -> None:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        for call in self._calls_in(st):
            self._handle_call(call)

        if isinstance(st, ast.Assign):
            v = self.eval(st.value)
            for t in st.targets:
                self._bind(t, v, st.value)
        elif isinstance(st, ast.AnnAssign) and st.value is not None:
            self._bind(st.target, self.eval(st.value), st.value)
        elif isinstance(st, ast.AugAssign):
            if isinstance(st.target, ast.Name):
                self.env[st.target.id] = _union(self.env.get(st.target.id, EMPTY), self.eval(st.value))
                if is_dynamic_string(st.value) or st.target.id in self.sql_dyn_vars:
                    self.sql_dyn_vars.add(st.target.id)
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            self._bind(st.target, self.eval(st.iter), None)
            self._block(st.body)
            self._block(st.body)
            self._block(st.orelse)
        elif isinstance(st, (ast.While, ast.If)):
            self._block(st.body)
            self._block(st.orelse)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, self.eval(item.context_expr), item.context_expr)
            self._block(st.body)
        elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            self._block(st.body)
            for h in st.handlers:
                self._block(h.body)
            self._block(st.orelse)
            self._block(st.finalbody)
        elif isinstance(st, ast.Match):
            for case in st.cases:
                self._block(case.body)

    def _calls_in(self, st: ast.stmt) -> list[ast.Call]:
        """Calls in this statement, excluding nested blocks (handled recursively)."""
        out: list[ast.Call] = []
        roots: list[ast.AST]
        if isinstance(st, (ast.For, ast.AsyncFor)):
            roots = [st.iter]
        elif isinstance(st, (ast.While, ast.If)):
            roots = [st.test]
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            roots = [i.context_expr for i in st.items]
        elif isinstance(st, (ast.Try, ast.Match)) or type(st).__name__ == "TryStar":
            roots = [st.subject] if isinstance(st, ast.Match) else []
        else:
            roots = [st]
        stack = list(roots)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(n, ast.Call):
                out.append(n)
            stack.extend(ast.iter_child_nodes(n))
        out.sort(key=lambda c: (c.lineno, c.col_offset))
        return out

    def _bind(self, target: ast.AST, v: Value, value_expr: ast.AST | None) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = _union(v, (name_taint(target.id), False))
            if value_expr is not None:
                self.kinds[target.id] = self.kind_of(value_expr)
                if is_dynamic_string(value_expr):
                    lit = literal_str(value_expr) or ""
                    if _SQL_KEYWORD.search(lit):
                        self.sql_dyn_vars.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt, v, None)
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
            key = f"self.{target.attr}"
            self.env[key] = _union(v, (name_taint(target.attr), False))
            if value_expr is not None:
                k = self.kind_of(value_expr)
                if k:
                    self.kinds[key] = k
        elif isinstance(target, ast.Starred):
            self._bind(target.value, v, None)

    # ---------------- calls / sinks ----------------
    def _arg_value(self, call: ast.Call, skip_kw: frozenset[str] = frozenset()) -> Value:
        vals = [self.eval(a) for a in call.args]
        vals += [self.eval(k.value) for k in call.keywords if k.arg not in skip_kw]
        return _union(*vals)

    def _emit(self, kind: SinkKind, api: str, call: ast.Call, value: Value, **extra) -> None:
        real = sorted({t for t in value[0] if t.category != PARAM}, key=lambda t: (t.category, t.name))
        params = {int(t.name) for t in value[0] if t.category == PARAM}
        ev = SinkEvent(
            kind=kind, api=api, location=loc(self.mod, call), function=self.ref.qualname,
            taints=real, sanitized=value[1], **extra,
        )
        sig = (kind, ev.location.line, ev.location.file, tuple(real), tuple(ev.via and [v.line for v in ev.via]))
        if sig not in self._seen:
            self._seen.add(sig)
            self.sinks.append(ev)
        for p in params:
            flows = self.summary.param_flows.setdefault(p, [])
            if not any(f.location == ev.location and f.kind == ev.kind and f.via == ev.via for f in flows):
                flows.append(ev.model_copy(update={"taints": []}))

    def _handle_call(self, call: ast.Call) -> None:
        chain = self.resolve(call.func)
        method = chain.rsplit(".", 1)[-1]
        self._config_checks(call, chain)

        # ---- SQL text: decide write vs delete from the statement itself ----
        if method in ("execute", "executemany", "exec_driver_sql") and call.args:
            sql = literal_str(call.args[0])
            arg0 = call.args[0]
            if is_dynamic_string(arg0) or (isinstance(arg0, ast.Name) and arg0.id in self.sql_dyn_vars):
                self.config.append(ConfigFact(kind="sql_string_build", location=loc(self.mod, call), detail=chain))
            if isinstance(arg0, ast.Call):
                inner = self.resolve(arg0.func)
                if inner in ("sqlalchemy.delete", "delete"):
                    self._record_delete_model(arg0, call)
                    return
            if sql:
                m_del = S.SQL_DELETE.match(sql)
                m_wr = S.SQL_WRITE.match(sql)
                vector = bool(S.SQL_VECTOR_HINT.search(sql))
                if m_del:
                    table = m_del.group(3).strip('"')
                    kind = SinkKind.vector_store if vector or self._table_is_vector(table) else SinkKind.db_write
                    self.deletes.append(DeleteOp(kind=kind, api=chain, location=loc(self.mod, call), function=self.ref.qualname, store=table))
                    self.summary.deletes.add(kind)
                    return
                if m_wr:
                    table = m_wr.group(2).strip('"')
                    kind = SinkKind.vector_store if vector or self._table_is_vector(table) else SinkKind.db_write
                    self._emit(kind, chain, call, self._arg_value(call), store=table)
                    return
                if re.match(r"^\s*select\b", sql, re.I):
                    return  # reads are not sinks

        del_kind = S.match_delete(chain)
        if del_kind:
            if chain in ("sqlalchemy.delete",):
                self._record_delete_model(call, call)
            else:
                self.deletes.append(DeleteOp(kind=del_kind, api=chain, location=loc(self.mod, call), function=self.ref.qualname))
                if not method.startswith(("expire", "pexpire")):
                    self.summary.deletes.add(del_kind)
            return

        kind = S.match_sink(chain)
        if kind:
            extra: dict = {}
            skip: frozenset[str] = frozenset()
            if kind == SinkKind.cache:
                ttl_kw = {k.arg for k in call.keywords} & {"ex", "px", "exat", "pxat", "keepttl"}
                extra["has_ttl"] = method in ("setex", "psetex") or bool(ttl_kw)
                skip = frozenset({"ex", "px", "exat", "pxat"})
                if call.args:
                    k = literal_str(call.args[0])
                    if k:
                        extra["store"] = k.split(":")[0].split("{")[0] or None
            if kind == SinkKind.db_write and method in ("add", "merge") and call.args:
                model = self._model_of(call.args[0])
                if model:
                    extra["store"] = model.table or model.name
                    if model.is_vector:
                        kind = SinkKind.vector_store
            if kind == SinkKind.http:
                url = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "url"), None)
                u = literal_str(url)
                if u:
                    extra["store"] = u.split("?")[0][:120]
                skip = frozenset({"timeout", "verify", "follow_redirects"})
            if kind == SinkKind.llm:
                skip = frozenset({"model", "temperature", "max_tokens", "config", "generation_config"})
            self._emit(kind, chain, call, self._arg_value(call, skip), **extra)
            return

        self._follow_repo_call(call, chain)

    def _table_is_vector(self, table: str) -> bool:
        return any(m.is_vector and m.table == table for m in self.index.models.values())

    def _model_of(self, e: ast.AST) -> PiiModel | None:
        if isinstance(e, ast.Call):
            return self.index.models.get(self.resolve(e.func).rsplit(".", 1)[-1])
        if isinstance(e, ast.Name):
            # look back for `x = Model(...)` in this function
            fn = self.ref.node
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == e.id for t in n.targets):
                    if isinstance(n.value, ast.Call):
                        m = self.index.models.get(self.resolve(n.value.func).rsplit(".", 1)[-1])
                        if m:
                            return m
        return None

    def _record_delete_model(self, del_call: ast.Call, at: ast.Call) -> None:
        model = self._model_of(ast.Call(func=del_call.args[0], args=[], keywords=[])) if del_call.args else None
        if del_call.args and isinstance(del_call.args[0], ast.Name):
            model = self.index.models.get(del_call.args[0].id)
        kind = SinkKind.vector_store if model and model.is_vector else SinkKind.db_write
        self.deletes.append(DeleteOp(kind=kind, api="sqlalchemy.delete", location=loc(self.mod, at),
                                     function=self.ref.qualname, store=(model.table or model.name) if model else None))
        self.summary.deletes.add(kind)

    # ---------------- cross-function ----------------
    def resolve_function_key(self, func: ast.AST) -> str | None:
        idx = self.index
        if isinstance(func, ast.Name):
            local = f"{self.mod.module}:{func.id}"
            if local in idx.functions:
                return local
            if func.id in self.mod.from_imports:
                base, name = self.mod.from_imports[func.id]
                m = idx.find_module(base)
                if m and f"{m.module}:{name}" in idx.functions:
                    return f"{m.module}:{name}"
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "self" and self.ref.class_name:
                k = f"{self.mod.module}:{self.ref.class_name}.{func.attr}"
                return k if k in idx.functions else None
            target = self.mod.imports.get(func.value.id)
            if target:
                m = idx.find_module(target)
                if m and f"{m.module}:{func.attr}" in idx.functions:
                    return f"{m.module}:{func.attr}"
        return None

    def _follow_repo_call(self, call: ast.Call, chain: str) -> None:
        key = self.resolve_function_key(call.func)
        if not key:
            return
        self.calls.append(key)
        summ = self.summaries.get(key)
        callee = self.index.functions[key]
        if summ:
            self.summary.deletes |= summ.deletes
        if not summ or not summ.param_flows:
            return
        params = callee.params
        arg_for: dict[int, ast.AST] = dict(enumerate(call.args))
        for kw in call.keywords:
            if kw.arg in params:
                arg_for[params.index(kw.arg)] = kw.value
        site = loc(self.mod, call)
        for i, flows in summ.param_flows.items():
            if i not in arg_for:
                continue
            v = self.eval(arg_for[i])
            if not v[0]:
                continue
            real = sorted({t for t in v[0] if t.category != PARAM}, key=lambda t: (t.category, t.name))
            pidx = {int(t.name) for t in v[0] if t.category == PARAM}
            for f in flows:
                ev = f.model_copy(update={
                    "taints": real, "sanitized": f.sanitized or v[1],
                    "via": [site, *f.via], "function": self.ref.qualname,
                })
                if real:
                    sig = (ev.kind, ev.location.line, ev.location.file, tuple(real), tuple(x.line for x in ev.via))
                    if sig not in self._seen:
                        self._seen.add(sig)
                        self.sinks.append(ev)
                for p in pidx:
                    lst = self.summary.param_flows.setdefault(p, [])
                    if not any(x.location == ev.location and x.via == ev.via for x in lst):
                        lst.append(ev.model_copy(update={"taints": []}))

    # ---------------- config / security observations in calls ----------------
    def _config_checks(self, call: ast.Call, chain: str) -> None:
        kws = {k.arg: k.value for k in call.keywords if k.arg}
        L = loc(self.mod, call)
        if isinstance(kws.get("debug"), ast.Constant) and kws["debug"].value is True:
            self.config.append(ConfigFact(kind="debug_enabled", location=L, detail=chain))
        if isinstance(kws.get("verify"), ast.Constant) and kws["verify"].value is False:
            self.config.append(ConfigFact(kind="tls_verify_disabled", location=L, detail=chain))
        last = chain.rsplit(".", 1)[-1]
        if last == "add_middleware" and call.args and self.resolve(call.args[0]).endswith("CORSMiddleware"):
            origins = kws.get("allow_origins")
            regex = kws.get("allow_origin_regex")
            if (origins is not None and "*" in ast.unparse(origins)) or (
                isinstance(regex, ast.Constant) and regex.value in (".*", "*")
            ):
                self.config.append(ConfigFact(kind="cors_wildcard", location=L, detail="allow_origins='*'"))
        if chain.endswith("flask_cors.CORS") or chain == "CORS":
            origins = kws.get("origins") or kws.get("resources")
            if origins is None or "*" in ast.unparse(origins):
                self.config.append(ConfigFact(kind="cors_wildcard", location=L, detail="flask-cors all origins"))
        if re.fullmatch(r"hashlib\.(md5|sha1|sha224|sha256|sha512|new)", chain):
            cats = {t.category for t in self._arg_value(call)[0]}
            if "credentials" in cats:
                self.config.append(ConfigFact(kind="weak_password_hash", location=L, detail=chain))
        if chain in ("logging.basicConfig", "logging.config.dictConfig", "logging.config.fileConfig", "structlog.configure") or chain.startswith("google.cloud.logging"):
            self.config.append(ConfigFact(kind="logging_configured", location=L, detail=chain))
        if last in ("TimedRotatingFileHandler",):
            when = kws.get("when") or (call.args[1] if len(call.args) > 1 else None)
            backup = kws.get("backupCount")
            interval = kws.get("interval")
            days = None
            if isinstance(backup, ast.Constant) and isinstance(backup.value, int):
                w = when.value.lower() if isinstance(when, ast.Constant) and isinstance(when.value, str) else "h"
                n = interval.value if isinstance(interval, ast.Constant) and isinstance(interval.value, int) else 1
                per_day = {"d": 1, "midnight": 1, "h": 1 / 24, "m": 1 / 1440, "s": 1 / 86400}.get(w, 7 if w.startswith("w") else 1 / 24)
                days = int(backup.value * n * per_day)
            self.config.append(ConfigFact(kind="logging_configured", location=L, detail=last))
            self.config.append(ConfigFact(kind="log_retention_days", location=L, detail=last, value=str(days) if days is not None else None))
        if last in ("RotatingFileHandler", "FileHandler", "StreamHandler", "WatchedFileHandler", "SysLogHandler"):
            self.config.append(ConfigFact(kind="logging_configured", location=L, detail=last))


# --------------------------------------------------------------------------
def analyze_functions(index: Index, rounds: int = 3) -> tuple[dict[str, FunctionAnalyzer], dict[str, Summary]]:
    summaries: dict[str, Summary] = {}
    results: dict[str, FunctionAnalyzer] = {}
    for _ in range(rounds):
        changed = False
        for key, ref in index.functions.items():
            fa = FunctionAnalyzer(ref, index, summaries).run()
            results[key] = fa
            old = summaries.get(key)
            new = fa.summary
            if old is None or _summary_sig(old) != _summary_sig(new):
                changed = True
            summaries[key] = new
        if not changed:
            break
    return results, summaries


def _summary_sig(s: Summary) -> tuple:
    return (
        tuple(sorted((i, len(v)) for i, v in s.param_flows.items())),
        tuple(sorted(s.deletes)),
    )
