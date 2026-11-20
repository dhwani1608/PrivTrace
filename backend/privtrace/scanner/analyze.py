"""Scanner entry point: workspace folder -> CodeFacts."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from privtrace.scanner.detectors.pii_names import classify_name
from privtrace.scanner.detectors.text_detectors import run_text_detectors
from privtrace.scanner.facts import CodeFacts, ConfigFact, FunctionInfo, Location
from privtrace.scanner.fetch import is_text_candidate, iter_files, read_text
from privtrace.scanner.flow.taint import FunctionAnalyzer, FunctionRef, Index, analyze_functions, loc
from privtrace.scanner.models_extract import extract_models
from privtrace.scanner.parsers.base import ParsedModule
from privtrace.scanner.parsers.python_ast import PARSERS

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket"}
_DELETE_NAME = re.compile(
    r"^(delete|erase|forget|remove|purge|destroy|wipe|deactivate)_?(user|account|profile|customer|me|member|person|my_?data|data|self)s?\b"
    r"|^(user|account|profile|customer)_?(delete|erase|removal|deletion|erasure)",
    re.I,
)
_AUTH_HINT = re.compile(r"(auth|current_user|get_user|verify|token|login|security|permission|require)", re.I)
_RETENTION_NAME = re.compile(r"(purge|cleanup|clean_up|retention|delete_old|prune|expire_old|remove_old|ttl_job)", re.I)
_CONSENT_NAME = re.compile(r"(consent|opt_?in|agree|accepted_terms|terms_accepted|privacy_notice|notice_version|purpose)", re.I)
_LOCAL_HOSTS = re.compile(r"^http://(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\]|[\w\-]+(:\d+)?(/|$)|[\w.\-]+\.(local|internal|svc|cluster\.local)\b)")
_ENV_DEBUG = re.compile(r"^\s*(DEBUG|FLASK_DEBUG|APP_DEBUG)\s*[=:]\s*['\"]?(true|1|yes|on)['\"]?\s*$", re.I | re.M)
_ENV_RETENTION = re.compile(r"^\s*([A-Z_]*LOG[A-Z_]*RETENTION[A-Z_]*|retention_days|log_retention_days)\s*[=:]\s*['\"]?(\d+)", re.I | re.M)
_NTP = re.compile(r"\b(ntp|chrony|chronyd|timesyncd|time\.google\.com|pool\.ntp\.org|ntpdate)\b", re.I)


def analyze_path(root: Path, root_name: str | None = None) -> CodeFacts:
    facts = CodeFacts(root_name=root_name or root.name)
    modules: list[ParsedModule] = []

    for rel, abspath in iter_files(root):
        facts.files.append(rel)
        if not is_text_candidate(rel):
            continue
        text = read_text(abspath)
        if text is None:
            continue
        facts.files_scanned += 1
        facts.detections.extend(run_text_detectors(rel, text))
        _config_text_checks(rel, text, facts)
        parser = PARSERS.get(abspath.suffix)
        if parser:
            mod = parser.parse(rel, text)
            if mod is None:
                facts.parse_errors.append(rel)
            else:
                modules.append(mod)
    facts.python_files = len(modules)
    if not modules:
        return facts

    index = _build_index(modules)
    facts.models = sorted(index.models.values(), key=lambda m: (m.file, m.line))
    results, summaries = analyze_functions(index)

    for key, fa in results.items():
        facts.sinks.extend(fa.sinks)
        facts.deletes.extend(fa.deletes)
        facts.config.extend(fa.config)

    for key, ref in index.functions.items():
        if isinstance(ref.node, ast.Module):
            continue
        info = _function_info(ref)
        summ = summaries.get(key)
        if summ:
            info.deletes = set(summ.deletes)
        info.calls = sorted(set(results[key].calls)) if key in results else []
        facts.functions.append(info)

    for mod in modules:
        _module_checks(mod, facts)

    facts.sinks.sort(key=lambda s: (s.location.file, s.location.line, s.kind))
    facts.config = _dedupe_config(facts.config)
    return facts


# --------------------------------------------------------------------------
def _build_index(modules: list[ParsedModule]) -> Index:
    index = Index(
        modules={m.module: m for m in modules},
        models=extract_models(modules),
        functions={},
        module_kinds={},
        class_kinds={},
    )
    for mod in modules:
        index.functions[f"{mod.module}:<module>"] = FunctionRef(f"{mod.module}:<module>", mod, mod.tree, "<module>")
        for node in mod.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                k = f"{mod.module}:{node.name}"
                index.functions[k] = FunctionRef(k, mod, node, node.name)
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        k = f"{mod.module}:{node.name}.{sub.name}"
                        index.functions[k] = FunctionRef(k, mod, sub, f"{node.name}.{sub.name}", node.name)

    # Object kinds bound at module level (logger = logging.getLogger(...), r = redis.Redis()).
    for mod in modules:
        fa = FunctionAnalyzer(index.functions[f"{mod.module}:<module>"], index, {})
        fa._block([s for s in mod.tree.body if isinstance(s, (ast.Assign, ast.AnnAssign, ast.With))])
        index.module_kinds[mod.module] = {k: v for k, v in fa.kinds.items() if v}
    # Object kinds bound on self in methods (self.cache = redis.Redis()).
    for ref in list(index.functions.values()):
        if ref.class_name:
            fa = FunctionAnalyzer(ref, index, {})
            fa._block(ref.node.body)
            ck = index.class_kinds.setdefault((ref.mod.module, ref.class_name), {})
            ck.update({k: v for k, v in fa.kinds.items() if k.startswith("self.") and v})
    return index


def _function_info(ref: FunctionRef) -> FunctionInfo:
    fn = ref.node
    info = FunctionInfo(qualname=ref.qualname, file=ref.mod.path, line=fn.lineno)
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in _ROUTE_METHODS:
            path = d.args[0].value if d.args and isinstance(d.args[0], ast.Constant) else None
            method = d.func.attr.upper()
            if d.func.attr in ("route", "api_route"):
                methods = next((k.value for k in d.keywords if k.arg == "methods"), None)
                ms = [e.value.upper() for e in getattr(methods, "elts", []) if isinstance(e, ast.Constant)]
                method = "DELETE" if "DELETE" in ms else (ms[0] if ms else "GET")
            info.route_method, info.route_path = method, path
    info.is_delete_handler = info.route_method == "DELETE" or bool(_DELETE_NAME.search(fn.name))
    return info


def function_has_auth(mod: ParsedModule, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in fn.decorator_list:
        if _AUTH_HINT.search(ast.unparse(d)) and not isinstance(d, ast.Call) or (
            isinstance(d, ast.Call) and any(_AUTH_HINT.search(ast.unparse(k)) for k in d.keywords if k.arg == "dependencies")
        ):
            return True
    for default in [*fn.args.defaults, *[d for d in fn.args.kw_defaults if d is not None]]:
        src = ast.unparse(default)
        if ("Depends" in src or "Security" in src) and _AUTH_HINT.search(src):
            return True
    for a in [*fn.args.args, *fn.args.kwonlyargs]:
        if a.annotation is not None and "Annotated" in ast.unparse(a.annotation) and _AUTH_HINT.search(ast.unparse(a.annotation)):
            return True
    return False


def _module_checks(mod: ParsedModule, facts: CodeFacts) -> None:
    for node in ast.walk(mod.tree):
        # DEBUG = True / app.debug = True / app.config["DEBUG"] = True
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is True:
            for t in node.targets:
                name = t.id if isinstance(t, ast.Name) else getattr(t, "attr", None)
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant):
                    name = str(t.slice.value)
                if name and name.upper() in ("DEBUG", "FLASK_DEBUG"):
                    facts.config.append(ConfigFact(kind="debug_enabled", location=loc(mod, node), detail=name))
        # LOG_RETENTION_DAYS = 30
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
            for t in node.targets:
                if isinstance(t, ast.Name) and re.search(r"LOG.*RETENTION|RETENTION.*LOG", t.id, re.I):
                    facts.config.append(ConfigFact(kind="log_retention_days", location=loc(mod, node), detail=t.id, value=str(node.value.value)))
        # literal http:// URLs to external hosts
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("http://"):
            if not _LOCAL_HOSTS.match(node.value):
                facts.config.append(ConfigFact(kind="insecure_http_url", location=loc(mod, node), detail=node.value.split("?")[0][:100]))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            if any(n and n.split(".")[0] in ("bcrypt", "argon2", "passlib") or (n or "").startswith(("werkzeug.security", "django.contrib.auth.hashers")) for n in names):
                facts.config.append(ConfigFact(kind="password_hash_lib", location=loc(mod, node), detail=", ".join(n for n in names if n)))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _RETENTION_NAME.search(node.name):
                facts.config.append(ConfigFact(kind="retention_mechanism", location=loc(mod, node), detail=node.name))
            if _CONSENT_NAME.search(node.name):
                facts.config.append(ConfigFact(kind="consent_logic", location=loc(mod, node), detail=node.name))
            for fi in facts.functions:
                if fi.file == mod.path and fi.line == node.lineno and fi.route_method and function_has_auth(mod, node):
                    facts.config.append(ConfigFact(kind="route_has_auth", location=loc(mod, node), detail=fi.qualname))
        # age gate: `age < 18`, `user.age >= 18`
        if isinstance(node, ast.Compare):
            src = ast.unparse(node)
            nums = [c.value for c in ast.walk(node) if isinstance(c, ast.Constant) and isinstance(c.value, int)]
            if re.search(r"\b(age|dob|date_of_birth|birth)", src, re.I) and any(13 <= n <= 21 for n in nums):
                facts.config.append(ConfigFact(kind="age_gate", location=loc(mod, node), detail=src[:80]))
        if isinstance(node, ast.Name) and _CONSENT_NAME.search(node.id) and isinstance(node.ctx, ast.Store):
            facts.config.append(ConfigFact(kind="consent_logic", location=loc(mod, node), detail=node.id))
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            c = classify_name(node.id)
            if c and not c.is_pii:
                facts.ambiguous_names.append(loc(mod, node))
        # SQL time-based purge: DELETE ... WHERE created_at < now() - interval
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search(r"delete\s+from\s+\w+\s+where\s+.*(created|updated|_at|timestamp).*(<|interval)", node.value, re.I | re.S):
            facts.config.append(ConfigFact(kind="retention_mechanism", location=loc(mod, node), detail="time-based DELETE"))


def _config_text_checks(rel: str, text: str, facts: CodeFacts) -> None:
    base = rel.rsplit("/", 1)[-1]
    lower = base.lower()
    if lower == ".env" or (lower.startswith(".env.") and not lower.endswith((".example", ".sample", ".template", ".dist"))):
        facts.config.append(ConfigFact(kind="committed_env_file", location=Location(file=rel, line=1), detail=base))
    is_config = lower.startswith(".env") or lower.endswith((".yaml", ".yml", ".ini", ".cfg", ".toml", ".conf", ".properties", ".json"))
    if is_config:
        for m in _ENV_DEBUG.finditer(text):
            line = text[: m.start()].count("\n") + 1
            facts.config.append(ConfigFact(kind="debug_enabled", location=Location(file=rel, line=line, snippet=m.group(0).strip()[:120]), detail=m.group(1)))
        for m in _ENV_RETENTION.finditer(text):
            line = text[: m.start()].count("\n") + 1
            facts.config.append(ConfigFact(kind="log_retention_days", location=Location(file=rel, line=line, snippet=m.group(0).strip()[:120]), detail=m.group(1), value=m.group(2)))
    if is_config or lower in ("dockerfile", "docker-compose.yml", "docker-compose.yaml") or lower.endswith((".tf", ".sh")):
        m = _NTP.search(text)
        if m:
            line = text[: m.start()].count("\n") + 1
            facts.config.append(ConfigFact(kind="time_sync_configured", location=Location(file=rel, line=line), detail=m.group(0)))


def _dedupe_config(items: list[ConfigFact]) -> list[ConfigFact]:
    seen: set[tuple] = set()
    out: list[ConfigFact] = []
    for c in items:
        k = (c.kind, c.location.file, c.location.line, c.detail)
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out
