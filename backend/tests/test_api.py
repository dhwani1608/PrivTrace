"""Phase 7: scan API (upload -> background job -> report)."""

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from privtrace.api.main import create_app
from privtrace.db.session import make_engine

APP_SRC = '''
import logging
from google import genai
log = logging.getLogger(__name__)
client = genai.Client()

def chat(email: str, message: str):
    log.info("chat from %s", email)
    return client.models.generate_content(model="m", contents=f"{email}: {message}")
'''


@pytest.fixture
def client():
    sm = sessionmaker(bind=make_engine("sqlite:///:memory:"), expire_on_commit=False)
    return TestClient(create_app(sm, run_inline=True))


def make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, src in files.items():
            zf.writestr(f"myapp/{name}", src)
    return buf.getvalue()


def test_packs_and_checklist(client):
    packs = client.get("/api/packs").json()
    assert {p["id"] for p in packs} >= {"dpdp-2023", "security-baseline"}
    q = client.get("/api/checklist", params={"packs": "dpdp,security"}).json()
    assert any(i["rule_id"] == "DPDP-PRC-01" for i in q)
    assert all(i["question"] for i in q)
    assert client.get("/api/checklist", params={"packs": "nope"}).status_code == 400


def test_zip_scan_end_to_end(client):
    r = client.post("/api/scans", data={"packs": "dpdp,security", "answers": json.dumps({"DPDP-PRC-01": "yes"}), "use_ai": "false"},
                    files={"file": ("myapp.zip", make_zip({"app.py": APP_SRC}), "application/zip")})
    assert r.status_code == 202, r.text
    sid = r.json()["scan_id"]
    st = client.get(f"/api/scans/{sid}").json()
    assert st["status"] == "done", st
    assert st["overall_score"] is not None
    rep = client.get(f"/api/scans/{sid}/report.json").json()
    assert rep["target"] == "myapp"
    assert any(x["rule_id"] == "DPDP-SEC-01" and x["status"] == "failed" for x in rep["results"])
    assert next(x for x in rep["results"] if x["rule_id"] == "DPDP-PRC-01")["status"] == "passed"
    html = client.get(f"/api/scans/{sid}/report.html").text
    assert "PrivTrace compliance exposure report" in html
    assert any(s["scan_id"] == sid for s in client.get("/api/scans").json())


def test_baseline_diff_via_api(client):
    first = client.post("/api/scans", data={"packs": "dpdp", "use_ai": "false"},
                        files={"file": ("a.zip", make_zip({"app.py": APP_SRC}), "application/zip")}).json()
    fixed_src = APP_SRC.replace('log.info("chat from %s", email)', 'log.info("chat")').replace(
        'contents=f"{email}: {message}"', 'contents=redact_pii(f"{email}: {message}")')
    second = client.post("/api/scans", data={"packs": "dpdp", "use_ai": "false", "baseline_id": first["scan_id"]},
                         files={"file": ("a.zip", make_zip({"app.py": fixed_src}), "application/zip")}).json()
    rep = client.get(f"/api/scans/{second['scan_id']}/report.json").json()
    assert rep["diff"]["overall_delta"] > 0
    assert {f["rule_id"] for f in rep["diff"]["fixed"]} >= {"DPDP-SEC-01", "DPDP-SEC-02"}


def test_input_validation(client):
    assert client.post("/api/scans", data={"packs": "dpdp"}).status_code == 400
    assert client.post("/api/scans", data={"packs": "dpdp", "github_url": "https://evil.example.org/x"}).status_code == 400
    assert client.post("/api/scans", data={"packs": "dpdp", "github_url": "file:///etc/passwd"}).status_code == 400
    bad_zip = client.post("/api/scans", data={"packs": "dpdp"}, files={"file": ("x.zip", b"not a zip", "application/zip")})
    assert bad_zip.status_code == 400
    bad_ans = client.post("/api/scans", data={"packs": "dpdp", "answers": '{"X": "maybe"}'},
                          files={"file": ("a.zip", make_zip({"a.py": "x=1"}), "application/zip")})
    assert bad_ans.status_code == 400
    assert client.get("/api/scans/nope").status_code == 404
    assert client.get("/api/scans/nope/report.html").status_code == 404


def test_zip_slip_reports_error(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "x = 1")
    sid = client.post("/api/scans", data={"packs": "dpdp", "use_ai": "false"},
                      files={"file": ("e.zip", buf.getvalue(), "application/zip")}).json()["scan_id"]
    st = client.get(f"/api/scans/{sid}").json()
    assert st["status"] == "error" and "unsafe path" in st["message"]
