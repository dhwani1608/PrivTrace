"""Phase 6: Gemini gateway. No network: a fake transport records every outgoing payload."""

import json
import re
import textwrap
from pathlib import Path

import pytest

from privtrace.ai.gateway import AIGateway, UnsafePayloadError, gateway_from_settings
from privtrace.ai.schemas import ClassificationResponse, FindingExplanation
from privtrace.core.config import Settings
from privtrace.core.redaction import redact
from privtrace.models.enums import RuleStatus
from privtrace.report.html_report import render_html
from privtrace.scan import run_scan
from privtrace.scanner.detectors.checksums import verhoeff_check_digit

FAKE_AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")
FAKE_PAN = "ABCPE1234F"
FAKE_EMAIL = "fake.person@example.com"
FAKE_PHONE = "+91 98765 00000"
FAKE_KEY = "AIza" + "Q" * 35
RAW_VALUES = [FAKE_AADHAAR, FAKE_PAN, FAKE_EMAIL, "98765 00000", FAKE_KEY]

# A file long enough that sending it whole would violate the 40-line limit.
APP = f'''
import logging
from google import genai
from fastapi import FastAPI
app = FastAPI(debug=True)
log = logging.getLogger(__name__)
client = genai.Client(api_key="{FAKE_KEY}")
DEMO_USER = {{"aadhaar": "{FAKE_AADHAAR}", "pan": "{FAKE_PAN}", "email": "{FAKE_EMAIL}", "phone": "{FAKE_PHONE}"}}
''' + "\n".join(f"def filler_{i}():\n    return {i}\n" for i in range(40)) + f'''

@app.post("/chat")
def chat(email: str, message: str, payload: dict):
    meta = payload.get("meta")
    log.info("chat %s {FAKE_PHONE}", email)
    return client.models.generate_content(model="m", contents=f"{{email}} {FAKE_PAN}: {{message}}")
'''


class RecordingTransport:
    model = "fake-gemini"

    def __init__(self, respond=None, fail=False):
        self.prompts: list[str] = []
        self.respond = respond
        self.fail = fail

    def generate_json(self, prompt, schema):
        self.prompts.append(prompt)
        if self.fail:
            raise ConnectionError("network down")
        if self.respond:
            return self.respond(prompt, schema)
        if schema is ClassificationResponse:
            return json.dumps({"items": [{"name": "meta", "is_personal_data": True, "category": "identity", "reason": "user metadata"}]})
        if schema is FindingExplanation:
            # a hostile model tries to flip the verdict; the schema must ignore it
            return json.dumps({"explanation": f"Data like {FAKE_EMAIL} reaches the model.", "suggested_fix": "Redact first.",
                               "suggested_diff": None, "status": "passed", "compliant": True})
        raise AssertionError(schema)


def repo(tmp_path: Path) -> Path:
    d = tmp_path / "app"
    d.mkdir(parents=True)
    (d / "app.py").write_text(textwrap.dedent(APP), encoding="utf-8")
    return d


def scan_with(tmp_path, transport):
    gw = AIGateway(transport, max_lines=40)
    return run_scan(repo(tmp_path), ["dpdp", "security"], ai=gw)[0], gw


def test_no_raw_pii_leaves_in_any_payload(tmp_path):
    t = RecordingTransport()
    scan_with(tmp_path, t)
    assert t.prompts, "expected AI calls"
    for p in t.prompts:
        for raw in RAW_VALUES:
            assert raw not in p, f"raw value leaked in payload: {raw}"
        # snippets are fenced; none may exceed 40 lines
        for block in re.findall(r"```python\n(.*?)```", p, re.S):
            assert len(block.strip("\n").splitlines()) <= 40
        # the whole file is never sent
        assert "filler_0" not in p or "filler_39" not in p


def test_ai_cannot_flip_status(tmp_path):
    without, _ = run_scan(repo(tmp_path / "a"), ["dpdp", "security"])
    with_ai, _ = scan_with(tmp_path / "b", RecordingTransport())
    assert [(r.rule_id, r.status) for r in without.results] == [(r.rule_id, r.status) for r in with_ai.results]
    assert with_ai.overall_score == without.overall_score
    llm = next(r for r in with_ai.results if r.rule_id == "DPDP-SEC-01")
    assert llm.status == RuleStatus.failed and llm.ai is not None
    assert not hasattr(llm.ai, "status")
    assert FAKE_EMAIL not in (llm.ai.explanation or "")  # AI output is redacted too


def test_graceful_fallback_on_failure(tmp_path):
    t = RecordingTransport(fail=True)
    result, gw = scan_with(tmp_path, t)
    assert gw.errors >= 1
    assert result.ai_used is False
    assert all(r.ai is None for r in result.results)
    assert result.overall_score is not None


def test_invalid_json_is_dropped(tmp_path):
    t = RecordingTransport(respond=lambda p, s: "not json at all")
    result, gw = scan_with(tmp_path, t)
    assert gw.errors >= 1 and all(r.ai is None for r in result.results)


def test_classification_is_informational(tmp_path):
    result, _ = scan_with(tmp_path, RecordingTransport())
    assert any(c["name"] == "meta" for c in result.ai_classifications)
    assert "AI-classified" in render_html(result)


def test_call_budget(tmp_path):
    t = RecordingTransport()
    gw = AIGateway(t, max_calls=2)
    run_scan(repo(tmp_path), ["dpdp", "security"], ai=gw)
    assert len(t.prompts) == 2


def test_guard_rejects_unredactable(monkeypatch):
    gw = AIGateway(RecordingTransport())
    monkeypatch.setattr("privtrace.ai.gateway.redact", lambda s: s)  # simulate a broken redactor
    with pytest.raises(UnsafePayloadError):
        gw.guard(f"email {FAKE_EMAIL}")


def test_snippet_window(tmp_path):
    d = repo(tmp_path)
    gw = AIGateway(RecordingTransport(), max_lines=40)
    snip = gw.snippet(d, "app.py", 100)
    assert len(snip.splitlines()) <= 40
    assert redact(snip) == snip


def test_gateway_disabled_without_config():
    assert gateway_from_settings(Settings(GEMINI_API_KEY=None, GEMINI_MODEL=None)) is None
    assert gateway_from_settings(Settings(GEMINI_API_KEY="x", GEMINI_MODEL=None)) is None
