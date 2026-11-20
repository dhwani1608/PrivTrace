from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from privtrace.api.main import create_app
from privtrace.cli import app as cli_app
from privtrace.packs.loader import PackLoadError, load_pack_file, load_packs, resolve_pack_ids

VALID_PACK = """
id: test-pack
name: Test Pack
short_name: TEST
jurisdiction: XX
version: "1"
source_url: https://example.org/act
rules:
  - id: TEST-SEC-01
    title: Something automated
    reference: "Section 1"
    reference_verified: false
    source_url: https://example.org/act#s1
    severity: high
    check_type: automated
    detector: some_check
    why_it_matters: Because.
    remediation: Fix it.
  - id: TEST-MAN-01
    title: Something manual
    reference: "Section 2"
    source_url: https://example.org/act#s2
    severity: low
    check_type: manual
    question: Do you have a policy?
    why_it_matters: Because.
    remediation: Write one.
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_health():
    client = TestClient(create_app())
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_valid_pack_loads_and_counts(tmp_path):
    pack = load_pack_file(_write(tmp_path, "t.yaml", VALID_PACK))
    s = pack.summary()
    assert s["automated"] == 1 and s["manual"] == 1 and s["unverified_references"] == 2


def test_unknown_detector_rejected(tmp_path):
    with pytest.raises(PackLoadError, match="unknown detector"):
        load_pack_file(_write(tmp_path, "t.yaml", VALID_PACK), known_checks={"other"})


def test_manual_rule_without_question_rejected(tmp_path):
    bad = VALID_PACK.replace("    question: Do you have a policy?\n", "")
    with pytest.raises(PackLoadError, match="need a 'question'"):
        load_pack_file(_write(tmp_path, "t.yaml", bad))


def test_rule_without_reference_rejected(tmp_path):
    bad = VALID_PACK.replace('reference: "Section 1"', 'reference: ""')
    with pytest.raises(PackLoadError):
        load_pack_file(_write(tmp_path, "t.yaml", bad))


def test_duplicate_rule_ids_rejected(tmp_path):
    bad = VALID_PACK.replace("TEST-MAN-01", "TEST-SEC-01")
    with pytest.raises(PackLoadError, match="duplicate rule id"):
        load_pack_file(_write(tmp_path, "t.yaml", bad))


def test_resolve_aliases(tmp_path):
    _write(tmp_path, "t.yaml", VALID_PACK)
    packs = load_packs(tmp_path, validate_detectors=False)
    assert resolve_pack_ids(["test"], packs) == ["test-pack"]
    with pytest.raises(PackLoadError):
        resolve_pack_ids(["nope"], packs)


def test_cli_version():
    result = CliRunner().invoke(cli_app, ["version"])
    assert result.exit_code == 0 and "privtrace" in result.output


def test_cli_packs_list_rejects_unknown_detector(tmp_path):
    _write(tmp_path, "t.yaml", VALID_PACK.replace("some_check", "definitely_not_registered"))
    result = CliRunner().invoke(cli_app, ["packs", "list", "--packs-dir", str(tmp_path)])
    assert result.exit_code == 2 and "unknown detector" in result.output
