"""Deterministic rule checks, referenced from pack YAML via `detector:`.

Every check: `(facts: CodeFacts, params: dict) -> CheckOutcome`.
Heuristic checks (consent, minimisation, children) never return `failed`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from privtrace.models.enums import RuleStatus
from privtrace.models.results import CheckOutcome, Evidence
from privtrace.rules.registry import register_check
from privtrace.scanner.facts import (
    STORAGE_SINKS,
    CodeFacts,
    ConfigFact,
    SinkEvent,
    SinkKind,
)

MAX_EVIDENCE = 25
SENSITIVE = {"credentials", "government_id", "financial", "health", "biometric"}
_TEST_PATH = re.compile(r"(^|/)(tests?|testing|__tests__)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


def _prod_sinks(facts: CodeFacts, *kinds: SinkKind) -> list[SinkEvent]:
    return [s for s in facts.sinks if s.kind in kinds and not is_test_path(s.location.file)]


def _sink_ev(s: SinkEvent) -> Evidence:
    names = ", ".join(sorted({t.name.split(".")[-1] for t in s.taints}))[:120] or "—"
    detail = f"{names} → {s.api}"
    if s.store:
        detail += f" [{s.store}]"
    if s.via:
        detail += " (via " + ", ".join(f"{v.file}:{v.line}" for v in s.via) + ")"
    return Evidence(file=s.location.file, line=s.location.line, snippet=s.location.snippet, detail=detail)


def _cfg_ev(c: ConfigFact) -> Evidence:
    return Evidence(file=c.location.file, line=c.location.line, snippet=c.location.snippet, detail=c.detail)


def _cap(evs: Iterable[Evidence]) -> list[Evidence]:
    out: list[Evidence] = []
    seen: set[tuple[str, int]] = set()
    for e in evs:
        if (e.file, e.line) in seen:
            continue
        seen.add((e.file, e.line))
        out.append(e)
        if len(out) >= MAX_EVIDENCE:
            break
    return out


def _outcome(status: RuleStatus, message: str, evidence: Iterable[Evidence] = ()) -> CheckOutcome:
    return CheckOutcome(status=status, message=message, evidence=_cap(evidence))


def _flag_sinks(facts: CodeFacts, kinds: tuple[SinkKind, ...], none_msg: str, clean_msg: str,
                hit_msg: str, hit_status: RuleStatus = RuleStatus.failed,
                categories: set[str] | None = None) -> CheckOutcome:
    sinks = _prod_sinks(facts, *kinds)
    if not sinks:
        return _outcome(RuleStatus.passed, none_msg)
    bad = [s for s in sinks if s.carries_pii and not s.sanitized
           and (categories is None or {t.category for t in s.taints} & categories)]
    if not bad:
        return _outcome(RuleStatus.passed, clean_msg)
    return _outcome(hit_status, hit_msg.format(n=len(bad)), (_sink_ev(s) for s in bad))


# =========================================================================
# Personal data flows
# =========================================================================
@register_check("pii_to_llm_unredacted")
def pii_to_llm_unredacted(facts: CodeFacts, params: dict) -> CheckOutcome:
    return _flag_sinks(
        facts, (SinkKind.llm,),
        none_msg="No LLM / AI API calls found.",
        clean_msg="LLM calls found; none receive personal data without a redaction step.",
        hit_msg="{n} LLM/AI call(s) receive personal data with no redaction on the path.",
    )


@register_check("pii_in_logs")
def pii_in_logs(facts: CodeFacts, params: dict) -> CheckOutcome:
    kinds = (SinkKind.log,)
    out = _flag_sinks(
        facts, kinds,
        none_msg="No logging calls found.",
        clean_msg="Logging calls found; none write personal data.",
        hit_msg="{n} logging call(s) write personal data or raw request bodies.",
    )
    if not params.get("include_print", True) and out.status == RuleStatus.failed:
        evs = [e for e in out.evidence if "→ print" not in e.detail]
        if not evs:
            return _outcome(RuleStatus.passed, "Only print() statements carry personal data.")
        out.evidence = evs
    return out


@register_check("pii_to_third_party")
def pii_to_third_party(facts: CodeFacts, params: dict) -> CheckOutcome:
    """Sharing with processors is allowed under contract, so this asks for review."""
    return _flag_sinks(
        facts, (SinkKind.http, SinkKind.analytics, SinkKind.llm),
        none_msg="No third-party API, analytics or AI calls found.",
        clean_msg="Third-party calls found; none receive personal data.",
        hit_msg="{n} call(s) send personal data to a third party (API, analytics or AI provider). "
                "Confirm a processor contract and, for cross-border transfers, that the destination is permitted.",
        hit_status=RuleStatus(params.get("hit_status", "needs_review")),
    )


@register_check("pii_to_vector_store_unredacted")
def pii_to_vector_store_unredacted(facts: CodeFacts, params: dict) -> CheckOutcome:
    return _flag_sinks(
        facts, (SinkKind.vector_store,),
        none_msg="No vector store writes found.",
        clean_msg="Vector store writes found; none embed personal data unredacted.",
        hit_msg="{n} vector-store write(s) embed personal data without redaction. Embedded text is hard to find and erase later.",
        hit_status=RuleStatus(params.get("hit_status", "needs_review")),
    )


@register_check("sensitive_data_unprotected_at_rest")
def sensitive_data_unprotected_at_rest(facts: CodeFacts, params: dict) -> CheckOutcome:
    sinks = [s for s in _prod_sinks(facts, *STORAGE_SINKS) if s.carries_pii and not s.sanitized
             and {t.category for t in s.taints} & (SENSITIVE - {"credentials"})]
    if not sinks:
        return _outcome(RuleStatus.passed, "No sensitive personal data (IDs, financial, health, biometric) written to stores without encryption/masking.")
    return _outcome(RuleStatus(params.get("hit_status", "needs_review")),
                    f"{len(sinks)} write(s) store sensitive identifiers/financial data with no encryption or masking step in code. "
                    "Column- or disk-level encryption may exist outside the code.",
                    (_sink_ev(s) for s in sinks))


# =========================================================================
# Erasure and retention
# =========================================================================
@register_check("erasure_covers_all_stores")
def erasure_covers_all_stores(facts: CodeFacts, params: dict) -> CheckOutcome:
    stores = {s.kind for s in _prod_sinks(facts, *STORAGE_SINKS) if s.carries_pii}
    if not stores:
        return _outcome(RuleStatus.not_assessable, "No stores holding personal data were found in code.")
    handlers = [f for f in facts.delete_handlers if not is_test_path(f.file)]
    writes = {k: [s for s in _prod_sinks(facts, k) if s.carries_pii] for k in stores}
    if not handlers:
        return _outcome(
            RuleStatus.failed,
            f"Personal data is stored in {', '.join(sorted(k.value for k in stores))} but no erasure/delete-user handler was found.",
            (_sink_ev(w[0]) for w in writes.values() if w),
        )
    covered: set[SinkKind] = set()
    for h in handlers:
        covered |= h.deletes
    missing = stores - covered
    h_ev = [Evidence(file=h.file, line=h.line, detail=f"delete handler {h.qualname}() deletes from: "
                     f"{', '.join(sorted(k.value for k in h.deletes)) or 'nothing'}") for h in handlers]
    if not missing:
        return _outcome(RuleStatus.passed, f"Erasure handler(s) delete from every store holding personal data ({', '.join(sorted(k.value for k in stores))}).", h_ev)
    miss_ev = [Evidence(file=w[0].location.file, line=w[0].location.line, snippet=w[0].location.snippet,
                        detail=f"personal data written to {k.value} — not deleted by any erasure handler")
               for k, w in sorted(writes.items()) if k in missing and w]
    return _outcome(
        RuleStatus.failed,
        f"Erasure handler(s) miss {len(missing)} store(s) holding personal data: {', '.join(sorted(k.value for k in missing))}.",
        [*h_ev, *miss_ev],
    )


@register_check("cache_pii_without_ttl")
def cache_pii_without_ttl(facts: CodeFacts, params: dict) -> CheckOutcome:
    caches = [s for s in _prod_sinks(facts, SinkKind.cache) if s.carries_pii]
    if not caches:
        return _outcome(RuleStatus.not_assessable if not _prod_sinks(facts, SinkKind.cache) else RuleStatus.passed,
                        "No cache writes holding personal data found.")
    bad = [s for s in caches if not s.has_ttl]
    if not bad:
        return _outcome(RuleStatus.passed, "Every cache write holding personal data sets a TTL.")
    return _outcome(RuleStatus.failed, f"{len(bad)} cache write(s) store personal data with no expiry (TTL).", (_sink_ev(s) for s in bad))


@register_check("retention_mechanism_present")
def retention_mechanism_present(facts: CodeFacts, params: dict) -> CheckOutcome:
    stores = {s.kind for s in _prod_sinks(facts, SinkKind.db_write, SinkKind.vector_store, SinkKind.file_write) if s.carries_pii}
    if not stores:
        return _outcome(RuleStatus.not_assessable, "No persistent stores holding personal data found.")
    mech = facts.config_of("retention_mechanism")
    if mech:
        return _outcome(RuleStatus.passed, "A retention / purge mechanism exists in code.", (_cfg_ev(c) for c in mech))
    return _outcome(RuleStatus.needs_review,
                    f"Personal data is persisted ({', '.join(sorted(k.value for k in stores))}) but no retention or purge job was found in code. "
                    "It may be configured in infrastructure.")


# =========================================================================
# Credentials, secrets, security configuration
# =========================================================================
@register_check("plaintext_passwords")
def plaintext_passwords(facts: CodeFacts, params: dict) -> CheckOutcome:
    stores = [s for s in _prod_sinks(facts, *STORAGE_SINKS, SinkKind.log)
              if not s.sanitized and any(t.category == "credentials" for t in s.taints)]
    weak = [c for c in facts.config_of("weak_password_hash") if not is_test_path(c.location.file)]
    if stores or weak:
        evs = [_sink_ev(s) for s in stores] + [_cfg_ev(c) for c in weak]
        parts = []
        if stores:
            parts.append(f"{len(stores)} place(s) store or log passwords without hashing")
        if weak:
            parts.append(f"{len(weak)} use(s) of a fast hash (MD5/SHA) for passwords")
        return _outcome(RuleStatus.failed, "; ".join(parts) + ".", evs)
    if facts.config_of("password_hash_lib"):
        return _outcome(RuleStatus.passed, "Passwords are handled with a password-hashing library (bcrypt/argon2/passlib).",
                        (_cfg_ev(c) for c in facts.config_of("password_hash_lib")))
    has_pw_field = any(f.category == "credentials" for m in facts.models for f in m.fields)
    if not has_pw_field:
        return _outcome(RuleStatus.not_assessable, "No password fields found.")
    return _outcome(RuleStatus.needs_review, "Password fields exist but no password-hashing library was found.")


@register_check("hardcoded_secrets")
def hardcoded_secrets(facts: CodeFacts, params: dict) -> CheckOutcome:
    hits = [d for d in facts.detections if d.data_category == "secret"
            and not d.file.lower().endswith((".example", ".sample", ".template", ".md"))]
    if not hits:
        return _outcome(RuleStatus.passed, "No hardcoded secrets or API keys found.")
    return _outcome(RuleStatus.failed, f"{len(hits)} hardcoded secret(s) / API key(s) found in the repository.",
                    (Evidence(file=d.file, line=d.line, snippet=d.snippet, detail=d.kind, confidence=d.confidence) for d in hits))


def _config_rule(kinds: tuple[str, ...], ok: str, bad: str, status: RuleStatus = RuleStatus.failed):
    def check(facts: CodeFacts, params: dict) -> CheckOutcome:
        hits = [c for c in facts.config_of(*kinds) if not is_test_path(c.location.file)]
        if not hits:
            return _outcome(RuleStatus.passed, ok)
        return _outcome(status, bad.format(n=len(hits)), (_cfg_ev(c) for c in hits))
    return check


register_check("committed_env_file")(_config_rule(
    ("committed_env_file",), "No .env file committed.", "{n} .env file(s) committed to the repository."))
register_check("debug_mode_enabled")(_config_rule(
    ("debug_enabled",), "Debug mode is not enabled in code or config.", "Debug mode enabled in {n} place(s)."))
register_check("cors_wildcard")(_config_rule(
    ("cors_wildcard",), "CORS is not open to all origins.", "CORS allows any origin ('*') in {n} place(s)."))
register_check("insecure_transport")(_config_rule(
    ("insecure_http_url", "tls_verify_disabled"), "No plain-HTTP external endpoints or disabled TLS verification found.",
    "{n} external call(s) use plain HTTP or disable TLS certificate verification."))
register_check("sql_string_building")(_config_rule(
    ("sql_string_build",), "No SQL built by string formatting/concatenation.", "{n} SQL statement(s) built with string formatting (injection risk)."))


@register_check("delete_endpoints_authenticated")
def delete_endpoints_authenticated(facts: CodeFacts, params: dict) -> CheckOutcome:
    routes = [f for f in facts.functions if f.route_method == "DELETE" and not is_test_path(f.file)]
    if not routes:
        return _outcome(RuleStatus.not_assessable, "No DELETE endpoints found.")
    authed = {(c.location.file, c.detail) for c in facts.config_of("route_has_auth")}
    bad = [f for f in routes if (f.file, f.qualname) not in authed]
    if not bad:
        return _outcome(RuleStatus.passed, "All DELETE endpoints declare an auth dependency.")
    return _outcome(RuleStatus.needs_review,
                    f"{len(bad)} DELETE endpoint(s) show no auth dependency. Anyone may be able to delete user data.",
                    (Evidence(file=f.file, line=f.line, detail=f"{f.route_method} {f.route_path or ''} → {f.qualname}()") for f in bad))


# =========================================================================
# Logging (CERT-In)
# =========================================================================
@register_check("logging_configured")
def logging_configured(facts: CodeFacts, params: dict) -> CheckOutcome:
    cfg = facts.config_of("logging_configured")
    if cfg:
        return _outcome(RuleStatus.passed, "Logging is configured in code.", (_cfg_ev(c) for c in cfg))
    return _outcome(RuleStatus(params.get("missing_status", "needs_review")),
                    "No logging configuration (basicConfig/dictConfig/handlers/structlog) found in code. "
                    "It may be configured by the platform.")


@register_check("log_retention_min_days")
def log_retention_min_days(facts: CodeFacts, params: dict) -> CheckOutcome:
    min_days = int(params.get("min_days", 180))
    vals = [c for c in facts.config_of("log_retention_days") if c.value is not None]
    if not vals:
        return _outcome(RuleStatus.needs_review, f"No log retention setting found in code/config; confirm logs are kept ≥ {min_days} days.")
    short = [c for c in vals if int(c.value) < min_days]
    if short:
        return _outcome(RuleStatus.failed, f"Log retention set below {min_days} days.",
                        (_cfg_ev(c).model_copy(update={"detail": f"{c.detail} = {c.value} days"}) for c in short))
    return _outcome(RuleStatus.passed, f"Log retention ≥ {min_days} days.", (_cfg_ev(c) for c in vals))


@register_check("time_sync_configured")
def time_sync_configured(facts: CodeFacts, params: dict) -> CheckOutcome:
    cfg = facts.config_of("time_sync_configured")
    if cfg:
        return _outcome(RuleStatus.passed, "NTP / time synchronisation configuration found.", (_cfg_ev(c) for c in cfg))
    return _outcome(RuleStatus.not_assessable, "Time synchronisation is usually configured on hosts, not in application code.")


# =========================================================================
# Heuristics: consent, minimisation, children. Never `failed`.
# =========================================================================
_COLLECTION_MODEL = re.compile(r"(signup|sign_up|register|registration|create|onboard|kyc|profile|user|customer|lead|contact|application|form)", re.I)
_CONSENT_FIELD = re.compile(r"(consent|opt_?in|agree|accept|terms|purpose|notice)", re.I)


def _collection_models(facts: CodeFacts):
    return [m for m in facts.models if m.model_kind == "pydantic" and m.fields and not is_test_path(m.file)
            and (_COLLECTION_MODEL.search(m.name) or len(m.fields) >= 2)]


@register_check("consent_captured_at_collection")
def consent_captured_at_collection(facts: CodeFacts, params: dict) -> CheckOutcome:
    models = _collection_models(facts)
    if not models:
        return _outcome(RuleStatus.not_assessable, "No request models collecting personal data found.")
    missing = [m for m in models if not any(_CONSENT_FIELD.search(f) for f in m.all_field_names)]
    if not missing:
        return _outcome(RuleStatus.passed, "Every request model collecting personal data has a consent/purpose field.")
    return _outcome(RuleStatus.needs_review,
                    f"{len(missing)} model(s) collect personal data with no consent / notice / purpose field. "
                    "Consent may be captured elsewhere — review.",
                    (Evidence(file=m.file, line=m.line, detail=f"{m.name}: {', '.join(f.name for f in m.fields)}") for m in missing))


@register_check("minimisation_sensitive_fields")
def minimisation_sensitive_fields(facts: CodeFacts, params: dict) -> CheckOutcome:
    cats = set(params.get("categories", ["government_id", "financial", "health", "biometric"]))
    models = _collection_models(facts)
    if not models:
        return _outcome(RuleStatus.not_assessable, "No request models collecting personal data found.")
    hits = [(m, [f for f in m.fields if f.category in cats]) for m in models]
    hits = [(m, fs) for m, fs in hits if fs]
    if not hits:
        return _outcome(RuleStatus.passed, "Collection models don't request government IDs, financial, health or biometric data.")
    return _outcome(RuleStatus.needs_review,
                    "Sensitive identifiers are collected. Confirm each is necessary for the stated purpose.",
                    (Evidence(file=m.file, line=f.line, detail=f"{m.name}.{f.name} ({f.category})") for m, fs in hits for f in fs))


@register_check("children_age_gate")
def children_age_gate(facts: CodeFacts, params: dict) -> CheckOutcome:
    age_fields = [(m, f) for m in facts.models for f in m.fields
                  if re.search(r"(age|dob|birth)", f.name, re.I) and not is_test_path(m.file)]
    gates = facts.config_of("age_gate")
    if gates:
        return _outcome(RuleStatus.passed, "An age check exists in code.", (_cfg_ev(c) for c in gates))
    if not age_fields:
        return _outcome(RuleStatus.not_assessable, "No age / date-of-birth fields found; cannot tell from code whether children use the service.")
    return _outcome(RuleStatus.needs_review, "Age / date-of-birth is collected but no age check was found.",
                    (Evidence(file=m.file, line=f.line, detail=f"{m.name}.{f.name}") for m, f in age_fields))


@register_check("identifiers_hardcoded")
def identifiers_hardcoded(facts: CodeFacts, params: dict) -> CheckOutcome:
    """Real-looking personal identifiers committed in code, fixtures or sample data."""
    strong = {"aadhaar", "card_number", "gstin", "pan"}
    hits = [d for d in facts.detections if d.data_category != "secret" and d.confidence >= 0.7
            and not d.file.lower().endswith(".md")]
    if not hits:
        return _outcome(RuleStatus.passed, "No personal identifiers found hardcoded in the repository.")
    status = RuleStatus.failed if any(d.kind in strong for d in hits) else RuleStatus.needs_review
    return _outcome(status, f"{len(hits)} personal identifier(s) (Aadhaar, PAN, phone, email, card...) appear in code or data files.",
                    (Evidence(file=d.file, line=d.line, snippet=d.snippet, detail=d.kind, confidence=d.confidence) for d in hits))
