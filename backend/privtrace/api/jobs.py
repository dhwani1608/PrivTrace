"""Scan job runner used by the API (and later by a Cloud Run Job).

Customer code lives only inside `workspace()`, which is deleted when the job ends.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from privtrace.ai.gateway import gateway_from_settings
from privtrace.db.models import ScanRecord
from privtrace.models.enums import ManualAnswerValue
from privtrace.models.results import ScanResult
from privtrace.scan import run_scan
from privtrace.scanner.fetch import FetchError, clone_github, extract_zip, workspace

log = logging.getLogger("privtrace.jobs")


def _update(sm: sessionmaker[Session], scan_id: str, **fields) -> None:
    with sm() as s:
        rec = s.get(ScanRecord, scan_id)
        if rec is None:
            return
        for k, v in fields.items():
            setattr(rec, k, v)
        s.commit()


def load_result(sm: sessionmaker[Session], scan_id: str | None) -> ScanResult | None:
    if not scan_id:
        return None
    with sm() as s:
        rec = s.get(ScanRecord, scan_id)
        if rec is None or not rec.result_json:
            return None
        return ScanResult.model_validate_json(rec.result_json)


def run_job(sm: sessionmaker[Session], scan_id: str, zip_bytes: bytes | None = None, use_ai: bool = True) -> None:
    with sm() as s:
        rec = s.get(ScanRecord, scan_id)
        if rec is None:
            return
        source_type, source_ref = rec.source_type, rec.source_ref
        packs = rec.packs.split(",")
        answers = {k: ManualAnswerValue(v) for k, v in json.loads(rec.answers_json or "{}").items()}
        baseline_id = rec.baseline_id

    stage = lambda name, msg: _update(sm, scan_id, status="running", stage=name, message=msg)  # noqa: E731
    try:
        with workspace() as ws:
            stage("fetching", "Fetching code")
            if source_type == "github":
                root = clone_github(source_ref, ws)
            else:
                zp = ws / "upload.zip"
                zp.write_bytes(zip_bytes or b"")
                root = extract_zip(zp, ws)
                zp.unlink(missing_ok=True)
            label = source_ref.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1] if source_type == "github" else Path(source_ref).stem

            gateway = gateway_from_settings() if use_ai else None
            result, _ = run_scan(
                root, packs, answers, target_label=label, baseline=load_result(sm, baseline_id),
                ai=gateway, on_stage=lambda name: stage(name, {"analyzing": "Parsing code and tracing data flows",
                                                             "evaluating": "Running compliance rules",
                                                             "explaining": "Writing AI explanations"}.get(name, name)),
            )
        # workspace is gone here: only the redacted result remains
        result.scan_id = scan_id
        _update(sm, scan_id, status="done", stage="done", message="Scan complete",
                overall_score=result.overall_score, risk_level=result.risk_level.value,
                result_json=result.model_dump_json())
    except FetchError as e:
        _update(sm, scan_id, status="error", stage="error", message=str(e))
    except Exception as e:  # never leak code or PII in the message
        log.exception("scan %s failed", scan_id)
        _update(sm, scan_id, status="error", stage="error", message=f"Scan failed ({type(e).__name__}).")
