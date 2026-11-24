"""Phase 3: AST parsing, sink detection, taint flow, data-flow graph."""

import textwrap
from pathlib import Path

from privtrace.scanner.analyze import analyze_path
from privtrace.scanner.facts import SinkKind
from privtrace.scanner.fetch import extract_zip, workspace
from privtrace.scanner.flow.graph import build_graph


def make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src).lstrip(), encoding="utf-8")
    return tmp_path


def pii_sinks(facts, kind):
    return [s for s in facts.sinks if s.kind == kind and s.carries_pii]


# ---------------------------------------------------------------- models
def test_models_extracted(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"models.py": """
        from pydantic import BaseModel
        from sqlalchemy import Column, String
        from sqlalchemy.orm import DeclarativeBase
        from pgvector.sqlalchemy import Vector

        class Base(DeclarativeBase): pass

        class SignupRequest(BaseModel):
            name: str
            email: str
            phone: str
            pan: str

        class User(Base):
            __tablename__ = "users"
            id = Column(String, primary_key=True)
            email = Column(String)
            password = Column(String)

        class Chunk(Base):
            __tablename__ = "chunks"
            id = Column(String, primary_key=True)
            embedding = Column(Vector(768))

        class Settings(BaseModel):
            timeout: int
    """}))
    models = {m.name: m for m in facts.models}
    assert {f.name for f in models["SignupRequest"].fields} == {"name", "email", "phone", "pan"}
    assert models["User"].table == "users"
    assert any(f.sensitive for f in models["User"].fields)  # password
    assert models["Chunk"].is_vector
    assert models["Settings"].fields == []


# ---------------------------------------------------------------- sinks + taint
def test_pii_to_log_and_llm(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import logging
        from google import genai

        logger = logging.getLogger(__name__)
        client = genai.Client()

        def chat(email: str, message: str):
            logger.info(f"chat from {email}")
            prompt = f"User {email} says: {message}"
            return client.models.generate_content(model=MODEL, contents=prompt)
    """}))
    assert pii_sinks(facts, SinkKind.log)
    llm = pii_sinks(facts, SinkKind.llm)
    assert llm and llm[0].taints[0].name == "email"
    assert not llm[0].sanitized


def test_redaction_marks_sanitized(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        from google import genai
        client = genai.Client()

        def chat(email: str, message: str):
            safe = redact_pii(f"{email}: {message}")
            return client.models.generate_content(model=M, contents=safe)
    """}))
    llm = [s for s in facts.sinks if s.kind == SinkKind.llm]
    assert llm and not llm[0].carries_pii and llm[0].sanitized


def test_no_pii_means_no_taint(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import logging
        logger = logging.getLogger(__name__)

        def health(counter: int):
            logger.info("ok %s", counter)
    """}))
    logs = [s for s in facts.sinks if s.kind == SinkKind.log]
    assert logs and not logs[0].carries_pii


def test_request_body_logged(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import logging
        from fastapi import FastAPI, Request
        app = FastAPI()
        log = logging.getLogger("x")

        @app.post("/chat")
        async def chat(request: Request):
            body = await request.json()
            log.info("body=%s", body)
    """}))
    assert any(t.category == "request_body" for s in pii_sinks(facts, SinkKind.log) for t in s.taints)


def test_pydantic_param_model(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import redis
        from pydantic import BaseModel
        r = redis.Redis()

        class Profile(BaseModel):
            email: str
            phone: str

        def cache_profile(p: Profile):
            r.set(f"profile:{p.email}", p.model_dump_json())

        def cache_with_ttl(p: Profile):
            r.set(f"profile:{p.email}", p.model_dump_json(), ex=3600)
    """}))
    caches = pii_sinks(facts, SinkKind.cache)
    by_fn = {s.function: s for s in caches}
    assert by_fn["cache_profile"].has_ttl is False
    assert by_fn["cache_with_ttl"].has_ttl is True
    assert by_fn["cache_profile"].store == "profile"


def test_cross_file_flow(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {
        "app/__init__.py": "",
        "app/llm.py": """
            from openai import OpenAI
            client = OpenAI()

            def ask(text):
                return client.chat.completions.create(model=M, messages=[{"role": "user", "content": text}])
        """,
        "app/main.py": """
            from .llm import ask

            def handler(phone: str):
                return ask(f"call {phone}")
        """,
    }))
    llm = pii_sinks(facts, SinkKind.llm)
    assert llm, facts.sinks
    assert llm[0].location.file == "app/llm.py"
    assert llm[0].via and llm[0].via[0].file == "app/main.py"
    assert llm[0].taints[0].category == "contact"


def test_db_write_and_vector_and_delete_handler(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import redis
        from fastapi import FastAPI, Depends
        from sqlalchemy.orm import Session
        from sqlalchemy import Column, String, text
        from pgvector.sqlalchemy import Vector
        app = FastAPI()
        r = redis.Redis()

        class User(Base):
            __tablename__ = "users"
            email = Column(String)

        class Memory(Base):
            __tablename__ = "memories"
            content = Column(String)
            embedding = Column(Vector(768))

        def save(db: Session, email: str, note: str):
            db.add(User(email=email))
            db.add(Memory(content=f"{email} {note}", embedding=vec))
            r.set(f"user:{email}", email)

        @app.delete("/users/{user_id}")
        def delete_user(user_id: str, db: Session = Depends(get_db)):
            db.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
    """}))
    kinds = {s.kind for s in facts.sinks if s.carries_pii}
    assert {SinkKind.db_write, SinkKind.vector_store, SinkKind.cache} <= kinds
    handler = next(f for f in facts.functions if f.is_delete_handler)
    assert handler.route_method == "DELETE"
    assert handler.deletes == {SinkKind.db_write}
    assert facts.pii_store_kinds() - handler.deletes == {SinkKind.vector_store, SinkKind.cache}


def test_delete_handler_via_helper_function(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import redis
        r = redis.Redis()

        def purge_cache(uid):
            r.delete(f"user:{uid}")

        def delete_account(uid):
            purge_cache(uid)
    """}))
    handler = next(f for f in facts.functions if f.qualname == "delete_account")
    assert handler.is_delete_handler and SinkKind.cache in handler.deletes


# ---------------------------------------------------------------- config facts
def test_config_facts(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {
        "app.py": """
            import hashlib, requests
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI(debug=True)
            app.add_middleware(CORSMiddleware, allow_origins=["*"])

            def store(password: str, user_id: str, cur):
                h = hashlib.md5(password.encode()).hexdigest()
                cur.execute(f"UPDATE users SET pw = '{h}' WHERE id = {user_id}")
                requests.post("http://partner-api.example.org/v1/notify", json={}, verify=False)
        """,
        ".env": "DEBUG=true\nSECRET_KEY=fake-not-real-123\n",
    }))
    kinds = {c.kind for c in facts.config}
    assert {"debug_enabled", "cors_wildcard", "weak_password_hash", "sql_string_build",
            "insecure_http_url", "tls_verify_disabled", "committed_env_file"} <= kinds


def test_clean_config_has_no_bad_facts(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import os
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware
        app = FastAPI()
        app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.org"])

        def get(cur, uid):
            cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
            return requests.get("https://api.example.org", timeout=5)
    """}))
    kinds = {c.kind for c in facts.config}
    assert not kinds & {"debug_enabled", "cors_wildcard", "sql_string_build", "insecure_http_url", "tls_verify_disabled"}


def test_log_retention_from_handler(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"log.py": """
        import logging
        from logging.handlers import TimedRotatingFileHandler
        h = TimedRotatingFileHandler("app.log", when="midnight", backupCount=30)
    """}))
    ret = facts.config_of("log_retention_days")
    assert ret and ret[0].value == "30"
    assert facts.config_of("logging_configured")


# ---------------------------------------------------------------- graph + workspace
def test_graph_marks_risky_edges(tmp_path):
    facts = analyze_path(make_repo(tmp_path, {"app.py": """
        import logging
        logger = logging.getLogger(__name__)
        def f(aadhaar_number):
            logger.info(aadhaar_number)
    """}))
    g = build_graph(facts.sinks)
    assert any(n.type == "source" for n in g.nodes)
    assert any(e.risky for e in g.edges)
    assert g.to_mermaid().startswith("flowchart LR")


def test_workspace_is_deleted():
    with workspace() as d:
        (d / "x.txt").write_text("x")
        saved = d
    assert not saved.exists()


def test_zip_slip_rejected(tmp_path):
    import zipfile

    import pytest

    from privtrace.scanner.fetch import FetchError

    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../evil.py", "x = 1")
    with workspace() as d, pytest.raises(FetchError):
        extract_zip(z, d)


def test_model_dump_exclude_and_include_are_respected(tmp_path):
    """`model_dump(exclude={"password"})` must not be reported as logging the password."""
    root = make_repo(tmp_path, {"app.py": textwrap.dedent('''
        import logging
        from fastapi import FastAPI
        from pydantic import BaseModel

        logger = logging.getLogger("x")
        app = FastAPI()

        class SignupRequest(BaseModel):
            email: str
            password: str

        @app.post("/a")
        def a(req: SignupRequest):
            payload = req.model_dump(exclude={"password"})
            logger.info(f"signup {payload}")

        @app.post("/b")
        def b(req: SignupRequest):
            logger.info("b %s", req.model_dump(include={"email"}))

        @app.post("/c")
        def c(req: SignupRequest, fields: set):
            logger.info("c %s", req.model_dump(exclude=fields))
    ''')})
    facts = analyze_path(root)
    names = {s.function: {t.name.rsplit(".", 1)[-1] for t in s.taints} for s in pii_sinks(facts, SinkKind.log)}
    assert "password" not in names["a"] and "email" in names["a"]
    assert names["b"] == {"email"} or ("password" not in names["b"] and "email" in names["b"])
    assert "password" in names["c"]  # dynamic exclusion is not trusted
