"""Phase 5: fix templates, rescan diff, HTML + JSON reports, CLI output."""

import json
import textwrap
from pathlib import Path

from typer.testing import CliRunner

from privtrace.cli import app as cli_app
from privtrace.models.enums import RuleStatus
from privtrace.models.results import ScanResult
from privtrace.report.html_report import render_html
from privtrace.scan import run_scan
from privtrace.scanner.detectors.checksums import verhoeff_check_digit

BAD = '''
import logging, redis
from google import genai
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"])
log = logging.getLogger(__name__)
r = redis.Redis()
client = genai.Client()
SUPPORT_CONTACT = "fake.support@example.com"

@app.post("/chat")
def chat(email: str, message: str):
    log.info("chat from %s", email)
    r.set(f"user:{email}", message)
    return client.models.generate_content(model="m", contents=f"{email}: {message}")

@app.delete("/users/{user_id}")
def delete_user(user_id: str, db=None):
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
'''

GOOD = '''
import logging, os, redis
from google import genai
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("ALLOWED_ORIGINS", "").split(","))
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
r = redis.Redis()
client = genai.Client()

@app.post("/chat")
def chat(email: str, message: str):
    log.info("chat request received")
    r.set(f"user:{email}", redact_pii(message), ex=3600)
    return client.models.generate_content(model="m", contents=redact_pii(f"{email}: {message}"))

@app.delete("/users/{user_id}")
def delete_user(user_id: str, db=None, user=Depends(get_current_user)):
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
    r.delete(f"user:{user_id}")
'''


def repo(tmp_path: Path, name: str, src: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "app.py").write_text(textwrap.dedent(src).lstrip(), encoding="utf-8")
    return d


def by_id(result: ScanResult, rule_id: str):
    return next(r for r in result.results if r.rule_id == rule_id)


def test_fix_templates(tmp_path):
    result, _ = run_scan(repo(tmp_path, "bad", BAD), ["dpdp", "security"])
    llm = by_id(result, "DPDP-SEC-01")
    assert llm.status == RuleStatus.failed
    assert "+    return client.models.generate_content(model=\"m\", contents=redact_pii(" in llm.fix_diff
    assert "ex=CACHE_TTL_SECONDS" in by_id(result, "DPDP-RET-01").fix_diff
    assert 'os.getenv("APP_DEBUG")' in by_id(result, "SECB-CFG-01").fix_diff
    assert "ALLOWED_ORIGINS" in by_id(result, "SECB-CFG-02").fix_diff
    erasure = by_id(result, "DPDP-ERA-01")
    assert erasure.status == RuleStatus.failed
    assert 'r.delete(f"user:{user_id}")' in erasure.fix_diff


def test_no_fix_for_passing_rules(tmp_path):
    result, _ = run_scan(repo(tmp_path, "good", GOOD), ["dpdp", "security"])
    for r in result.results:
        if r.status == RuleStatus.passed:
            assert r.fix_diff is None


def test_fixed_version_scores_higher_and_diff(tmp_path):
    before, _ = run_scan(repo(tmp_path, "bad", BAD), ["dpdp", "security"])
    after, _ = run_scan(repo(tmp_path, "good", GOOD), ["dpdp", "security"], baseline=before)
    assert after.overall_score > before.overall_score
    d = after.diff
    assert d["overall_delta"] > 0
    fixed = {f["rule_id"] for f in d["fixed"]}
    assert {"DPDP-SEC-01", "DPDP-SEC-02", "DPDP-ERA-01", "SECB-CFG-01", "SECB-CFG-02"} <= fixed
    assert not d["regressed"]


def test_html_report_sections_and_redaction(tmp_path):
    fake_aadhaar = "23456789012" + verhoeff_check_digit("23456789012")
    src = BAD + f'\nTEST_USER_AADHAAR = "{fake_aadhaar}"\n'
    result, _ = run_scan(repo(tmp_path, "bad", src), ["dpdp", "security"])
    html = render_html(result)
    for section in ("1. Summary", "2. Data-flow map", "3. Findings by framework", "4. Manual checklist answers",
                    "5. Coverage and limitations", "6. Disclaimer", "How the score is calculated", "Not legal advice"):
        assert section in html
    assert "<svg" in html and "edge risky" in html
    assert fake_aadhaar not in html
    assert "fake.support@example.com" not in html
    assert "[REDACTED:" in html
    js = result.model_dump_json()
    assert fake_aadhaar not in js and "fake.support@example.com" not in js
    assert "compliant" not in html.lower().replace("non-compliance", "").replace("compliance", "")


def test_json_roundtrip(tmp_path):
    result, _ = run_scan(repo(tmp_path, "bad", BAD), ["dpdp"])
    again = ScanResult.model_validate_json(result.model_dump_json())
    assert again.overall_score == result.overall_score
    assert again.results[0].rule_id == result.results[0].rule_id


def test_cli_scan_writes_reports_and_rescan_diff(tmp_path, monkeypatch):
    target = repo(tmp_path, "bad", BAD)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    r1 = runner.invoke(cli_app, ["scan", str(target), "--packs", "dpdp,security",
                                 "--out", str(tmp_path / "r.html"), "--out", str(tmp_path / "r.json"),
                                 "--answer", "DPDP-PRC-01=yes"])
    assert r1.exit_code == 0, r1.output
    assert (tmp_path / "r.html").exists()
    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert data["manual_answers"]["DPDP-PRC-01"] == "yes"
    assert "DPDP-SEC-01" in r1.output
    # rescan the same folder after a "fix": history gives a diff
    (target / "app.py").write_text(textwrap.dedent(GOOD).lstrip(), encoding="utf-8")
    r2 = runner.invoke(cli_app, ["scan", str(target), "--packs", "dpdp,security", "--out", str(tmp_path / "r2.json")])
    assert r2.exit_code == 0, r2.output
    assert "Since last scan" in r2.output
    assert json.loads((tmp_path / "r2.json").read_text(encoding="utf-8"))["diff"]["overall_delta"] > 0


def test_cli_fail_under(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli_app, ["scan", str(repo(tmp_path, "bad", BAD)), "--no-history", "--fail-under", "90"])
    assert r.exit_code == 1
