"""Phase 4: every rule check has a passing and a failing case; engine + scoring tests."""

import textwrap
from pathlib import Path

import pytest

from privtrace.models.enums import CheckType, ManualAnswerValue, RiskLevel, RuleStatus, Severity
from privtrace.models.results import CheckOutcome, RuleResult
from privtrace.packs.loader import load_packs
from privtrace.packs.schema import Pack
from privtrace.report.scoring import overall_score, risk_level, score_pack
from privtrace.rules.engine import combine_hybrid, evaluate
from privtrace.rules.registry import get_check, registered_checks
from privtrace.scanner.analyze import analyze_path

P, F, R, NA = RuleStatus.passed, RuleStatus.failed, RuleStatus.needs_review, RuleStatus.not_assessable


def facts_for(tmp_path: Path, files: dict[str, str]):
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src).lstrip(), encoding="utf-8")
    return analyze_path(tmp_path)


def run(name, facts, **params):
    return get_check(name)(facts, params)


# (check name, bad files, expected bad status, good files)
CASES = [
    ("pii_to_llm_unredacted",
     {"a.py": """
        from google import genai
        c = genai.Client()
        def chat(email, msg):
            return c.models.generate_content(model=M, contents=f"{email}: {msg}")
     """}, F,
     {"a.py": """
        from google import genai
        c = genai.Client()
        def chat(email, msg):
            return c.models.generate_content(model=M, contents=redact(f"{email}: {msg}"))
     """}),
    ("pii_in_logs",
     {"a.py": """
        import logging
        log = logging.getLogger(__name__)
        def f(phone): log.info("phone=%s", phone)
     """}, F,
     {"a.py": """
        import logging
        log = logging.getLogger(__name__)
        def f(user_id): log.info("user=%s", user_id)
     """}),
    ("pii_to_third_party",
     {"a.py": """
        import requests
        def f(email): requests.post("https://sms.example.org/send", json={"to": email})
     """}, R,
     {"a.py": """
        import requests
        def f(order_id): requests.post("https://sms.example.org/send", json={"id": order_id})
     """}),
    ("pii_to_vector_store_unredacted",
     {"a.py": """
        import chromadb
        col = chromadb.Client().get_or_create_collection("docs")
        def f(email, text): col.add(documents=[f"{email} {text}"], ids=["1"])
     """}, R,
     {"a.py": """
        import chromadb
        col = chromadb.Client().get_or_create_collection("docs")
        def f(doc_text): col.add(documents=[doc_text], ids=["1"])
     """}),
    ("sensitive_data_unprotected_at_rest",
     {"a.py": """
        import redis
        r = redis.Redis()
        def f(pan_number): r.set("k", pan_number, ex=60)
     """}, R,
     {"a.py": """
        import redis
        r = redis.Redis()
        def f(pan_number): r.set("k", encrypt(pan_number), ex=60)
     """}),
    ("erasure_covers_all_stores",
     {"a.py": """
        import redis
        r = redis.Redis()
        def save(db: Session, email):
            db.add(User(email=email))
            r.set(f"u:{email}", email, ex=60)
        def delete_user(db: Session, uid):
            db.execute(text("DELETE FROM users WHERE id=:i"), {"i": uid})
     """}, F,
     {"a.py": """
        import redis
        r = redis.Redis()
        def save(db: Session, email):
            db.add(User(email=email))
            r.set(f"u:{email}", email, ex=60)
        def delete_user(db: Session, uid):
            db.execute(text("DELETE FROM users WHERE id=:i"), {"i": uid})
            r.delete(f"u:{uid}")
     """}),
    ("cache_pii_without_ttl",
     {"a.py": """
        import redis
        r = redis.Redis()
        def f(email): r.set("k", email)
     """}, F,
     {"a.py": """
        import redis
        r = redis.Redis()
        def f(email): r.setex("k", 60, email)
     """}),
    ("retention_mechanism_present",
     {"a.py": """
        def save(db: Session, email): db.add(User(email=email))
     """}, R,
     {"a.py": """
        def save(db: Session, email): db.add(User(email=email))
        def purge_old_users(db: Session): db.execute(text("DELETE FROM users WHERE created_at < now() - interval '1 year'"))
     """}),
    ("plaintext_passwords",
     {"a.py": """
        def signup(db: Session, email, password):
            db.add(User(email=email, password=password))
     """}, F,
     {"a.py": """
        import bcrypt
        def signup(db: Session, email, password):
            db.add(User(email=email, password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt())))
     """}),
    ("hardcoded_secrets",
     {"a.py": 'GEMINI_API_KEY = "AIza' + "F" * 35 + '"\n'}, F,
     {"a.py": 'import os\nGEMINI_API_KEY = os.environ["GEMINI_API_KEY"]\n'}),
    ("committed_env_file", {".env": "X=1\n"}, F, {".env.example": "X=\n"}),
    ("debug_mode_enabled",
     {"a.py": "from fastapi import FastAPI\napp = FastAPI(debug=True)\n"}, F,
     {"a.py": "from fastapi import FastAPI\napp = FastAPI()\n"}),
    ("cors_wildcard",
     {"a.py": "app.add_middleware(CORSMiddleware, allow_origins=['*'])\nfrom fastapi.middleware.cors import CORSMiddleware\n"}, F,
     {"a.py": "from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(CORSMiddleware, allow_origins=['https://x.example.org'])\n"}),
    ("insecure_transport",
     {"a.py": "import requests\nrequests.get('http://api.partner.example.org/v1')\n"}, F,
     {"a.py": "import requests\nrequests.get('https://api.partner.example.org/v1', timeout=5)\n"}),
    ("sql_string_building",
     {"a.py": "def f(cur, uid):\n    cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"}, F,
     {"a.py": "def f(cur, uid):\n    cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"}),
    ("delete_endpoints_authenticated",
     {"a.py": """
        from fastapi import FastAPI
        app = FastAPI()
        @app.delete("/users/{uid}")
        def delete_user(uid: str): ...
     """}, R,
     {"a.py": """
        from fastapi import FastAPI, Depends
        app = FastAPI()
        @app.delete("/users/{uid}")
        def delete_user(uid: str, user=Depends(get_current_user)): ...
     """}),
    ("logging_configured",
     {"a.py": "x = 1\n"}, R,
     {"a.py": "import logging\nlogging.basicConfig(level=logging.INFO)\n"}),
    ("log_retention_min_days",
     {"a.py": "from logging.handlers import TimedRotatingFileHandler\nh = TimedRotatingFileHandler('a.log', when='D', backupCount=30)\n"}, F,
     {"a.py": "from logging.handlers import TimedRotatingFileHandler\nh = TimedRotatingFileHandler('a.log', when='D', backupCount=200)\n"}),
    ("time_sync_configured", {"a.py": "x = 1\n"}, NA, {"docker-compose.yml": "services:\n  ntp:\n    image: cturra/ntp\n"}),
    ("consent_captured_at_collection",
     {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            name: str
            email: str
     """}, R,
     {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            name: str
            email: str
            consent_given: bool
            notice_version: str
     """}),
    ("minimisation_sensitive_fields",
     {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            email: str
            pan: str
     """}, R,
     {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            email: str
            name: str
     """}),
    ("children_age_gate",
     {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            email: str
            date_of_birth: str
     """}, R,
     {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            email: str
            age: int
        def check(req):
            if req.age < 18:
                raise ValueError("parental consent required")
     """}),
    ("identifiers_hardcoded",
     {"fixtures/users.csv": "name,card\nFake User,4111 1111 1111 1111\n"}, F,
     {"fixtures/users.csv": "name,card\nFake User,XXXX\n"}),
]


@pytest.mark.parametrize("name,bad,bad_status,good", CASES, ids=[c[0] for c in CASES])
def test_check_fail_and_pass(tmp_path, name, bad, bad_status, good):
    bad_out = run(name, facts_for(tmp_path / "bad", bad))
    assert bad_out.status == bad_status, bad_out.message
    good_out = run(name, facts_for(tmp_path / "good", good))
    assert good_out.status == P, good_out.message


def test_every_registered_check_has_a_case():
    assert registered_checks() == {c[0] for c in CASES}


def test_heuristic_checks_never_fail(tmp_path):
    facts = facts_for(tmp_path, {"a.py": """
        from pydantic import BaseModel
        class SignupRequest(BaseModel):
            email: str
            aadhaar: str
            dob: str
    """})
    for name in ("consent_captured_at_collection", "minimisation_sensitive_fields", "children_age_gate"):
        assert run(name, facts).status != F


def test_evidence_is_redacted(tmp_path):
    facts = facts_for(tmp_path, {"a.py": """
        import logging
        log = logging.getLogger(__name__)
        def f(): log.info("contact fake.user@example.com")
    """})
    # literal email in a log line is caught by the detector; snippet must not contain it
    for d in facts.detections:
        assert "fake.user@example.com" not in d.snippet


# --------------------------------------------------------------- engine
def test_hybrid_combination():
    fail = CheckOutcome(status=F, message="x")
    review = CheckOutcome(status=R, message="x")
    ok = CheckOutcome(status=P, message="x")
    assert combine_hybrid(fail, ManualAnswerValue.yes)[0] == F  # code evidence wins
    assert combine_hybrid(review, ManualAnswerValue.yes)[0] == P
    assert combine_hybrid(review, ManualAnswerValue.no)[0] == F
    assert combine_hybrid(review, ManualAnswerValue.not_sure)[0] == R
    assert combine_hybrid(review, None)[0] == R
    assert combine_hybrid(ok, ManualAnswerValue.no)[0] == F


def test_manual_answers_flow_into_results(tmp_path):
    packs = load_packs()
    facts = facts_for(tmp_path, {"a.py": "x = 1\n"})
    res = evaluate([packs["dpdp-2023"]], facts, {"DPDP-PRC-01": ManualAnswerValue.yes, "DPDP-BRE-01": ManualAnswerValue.no})
    by = {r.rule_id: r for r in res}
    assert by["DPDP-PRC-01"].status == P
    assert by["DPDP-BRE-01"].status == F
    assert by["DPDP-GRV-01"].status == R  # unanswered


def test_all_shipped_packs_valid_and_referenced():
    packs = load_packs()
    assert {"dpdp-2023", "security-baseline"} <= set(packs)
    for p in packs.values():
        assert 8 <= len(p.rules) <= 15, p.id
        assert any(r.check_type == CheckType.manual for r in p.rules), p.id
        for r in p.rules:
            assert r.reference and str(r.source_url).startswith("https://")


def test_legal_todo_lists_every_unverified_reference():
    todo = (Path(__file__).resolve().parents[2] / "docs" / "LEGAL_REVIEW_TODO.md").read_text(encoding="utf-8")
    for p in load_packs().values():
        for r in p.unverified_references:
            assert f"`{r.id}`" in todo, f"{r.id} missing from LEGAL_REVIEW_TODO.md — run `privtrace packs legal-todo`"


# --------------------------------------------------------------- scoring
def _rr(rule_id, status, sev, ct=CheckType.automated, ans=None):
    return RuleResult(pack_id="p", rule_id=rule_id, title="t", status=status, severity=sev, check_type=ct,
                      reference="r", reference_verified=False, source_url="https://x.org",
                      why_it_matters="w", remediation="r", manual_answer=ans)


def _pack():
    return Pack.model_validate({
        "id": "p", "name": "P", "short_name": "P", "jurisdiction": "XX", "version": "1",
        "source_url": "https://x.org",
        "rules": [{"id": "P-A-01", "title": "t", "reference": "r", "source_url": "https://x.org",
                   "severity": "low", "check_type": "manual", "question": "q?", "why_it_matters": "w", "remediation": "r"}],
    })


def test_score_formula():
    results = [
        _rr("A-B-1", P, Severity.critical),   # 10 passed
        _rr("A-B-2", F, Severity.high),       # 6 failed
        _rr("A-B-3", P, Severity.medium),     # 3 passed
        _rr("A-B-4", R, Severity.critical),   # excluded
        _rr("A-B-5", NA, Severity.high),      # excluded
        _rr("A-B-6", P, Severity.low, CheckType.manual, ManualAnswerValue.yes),  # 1 passed
    ]
    ps = score_pack(_pack(), results)
    assert ps.passed_weight == 14 and ps.assessed_weight == 20
    assert ps.score == 70.0
    assert ps.coverage.total == 6 and ps.coverage.not_assessable == 1 and ps.coverage.manual_answered == 1
    assert ps.coverage.automated_checked == 3
    assert risk_level(results) == RiskLevel.high


def test_overall_is_weighted_and_handles_empty():
    a = score_pack(_pack(), [_rr("A-B-1", P, Severity.critical)])
    b = score_pack(_pack(), [_rr("A-B-1", F, Severity.low)])
    assert overall_score([a, b]) == round(100 * 10 / 11, 1)
    assert overall_score([score_pack(_pack(), [_rr("A-B-1", R, Severity.low)])]) is None
    assert risk_level([]) == RiskLevel.low
