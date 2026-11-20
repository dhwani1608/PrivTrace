"""FastAPI application: packs, checklist, scans, reports."""

from __future__ import annotations

import json
import re
import uuid

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from privtrace import DISCLAIMER, __version__
from privtrace.api.jobs import load_result, run_job
from privtrace.core.config import get_settings
from privtrace.core.redaction import install_log_redaction
from privtrace.db.models import ScanRecord
from privtrace.db.session import get_sessionmaker
from privtrace.models.enums import CheckType, ManualAnswerValue
from privtrace.packs.loader import PackLoadError, load_packs, resolve_pack_ids
from privtrace.report.html_report import render_html

_GITHUB = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+?(\.git)?/?$")


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    stage: str
    message: str
    source_type: str
    source_ref: str
    packs: list[str]
    overall_score: float | None = None
    risk_level: str | None = None
    baseline_id: str | None = None
    created_at: str


def _status(rec: ScanRecord) -> ScanStatus:
    return ScanStatus(
        scan_id=rec.id, status=rec.status, stage=rec.stage, message=rec.message, source_type=rec.source_type,
        source_ref=rec.source_ref, packs=rec.packs.split(","), overall_score=rec.overall_score,
        risk_level=rec.risk_level, baseline_id=rec.baseline_id, created_at=rec.created_at.isoformat(),
    )


def create_app(sessionmaker_: sessionmaker[Session] | None = None, run_inline: bool = False) -> FastAPI:
    settings = get_settings()
    install_log_redaction()
    app = FastAPI(title="PrivTrace API", version=__version__, description="Multi-framework compliance scanner. " + DISCLAIMER)
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"],
    )

    def sm() -> sessionmaker[Session]:
        return sessionmaker_ or get_sessionmaker()

    def packs_or_500():
        try:
            return load_packs()
        except PackLoadError as e:
            raise HTTPException(500, str(e)) from e

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "version": __version__, "ai_configured": settings.gemini_configured}

    @app.get("/api/packs")
    def list_packs() -> list[dict[str, object]]:
        return [p.summary() for p in packs_or_500().values()]

    @app.get("/api/checklist")
    def checklist(packs: str) -> list[dict[str, object]]:
        all_packs = packs_or_500()
        try:
            ids = resolve_pack_ids(packs.split(","), all_packs)
        except PackLoadError as e:
            raise HTTPException(400, str(e)) from e
        out = []
        for pid in ids:
            p = all_packs[pid]
            for r in p.rules:
                if r.check_type in (CheckType.manual, CheckType.hybrid) and r.question:
                    out.append({"pack_id": pid, "pack": p.short_name, "rule_id": r.id, "title": r.title,
                                "question": r.question, "check_type": r.check_type.value,
                                "severity": r.severity.value, "reference": r.reference})
        return out

    @app.post("/api/scans", status_code=202)
    async def create_scan(
        background: BackgroundTasks,
        packs: str = Form(...),
        github_url: str | None = Form(None),
        answers: str = Form("{}"),
        baseline_id: str | None = Form(None),
        use_ai: bool = Form(True),
        file: UploadFile | None = File(None),
    ) -> ScanStatus:
        all_packs = packs_or_500()
        try:
            ids = resolve_pack_ids(packs.split(","), all_packs)
        except PackLoadError as e:
            raise HTTPException(400, str(e)) from e
        if not ids:
            raise HTTPException(400, "select at least one pack")
        try:
            parsed = {k: ManualAnswerValue(v).value for k, v in json.loads(answers or "{}").items()}
        except (ValueError, AttributeError) as e:
            raise HTTPException(400, "answers must be a JSON object of rule_id -> yes|no|not_sure") from e

        zip_bytes: bytes | None = None
        if github_url:
            if not _GITHUB.match(github_url.strip()):
                raise HTTPException(400, "only public https://github.com/<owner>/<repo> URLs are supported")
            source_type, source_ref = "github", github_url.strip()
        elif file is not None:
            limit = settings.max_upload_mb * 1024 * 1024
            zip_bytes = await file.read(limit + 1)
            if len(zip_bytes) > limit:
                raise HTTPException(413, f"upload larger than {settings.max_upload_mb} MB")
            if not zip_bytes.startswith(b"PK"):
                raise HTTPException(400, "upload must be a .zip file")
            source_type, source_ref = "zip", (file.filename or "upload.zip")[:200]
        else:
            raise HTTPException(400, "provide github_url or a zip file")

        scan_id = uuid.uuid4().hex[:12]
        with sm()() as s:
            if baseline_id and s.get(ScanRecord, baseline_id) is None:
                raise HTTPException(404, "baseline scan not found")
            rec = ScanRecord(id=scan_id, source_type=source_type, source_ref=source_ref, packs=",".join(ids),
                             answers_json=json.dumps(parsed), baseline_id=baseline_id)
            s.add(rec)
            s.commit()
            status = _status(rec)
        if run_inline:
            run_job(sm(), scan_id, zip_bytes, use_ai)
        else:
            background.add_task(run_job, sm(), scan_id, zip_bytes, use_ai)
        return status

    @app.post("/api/scans/{scan_id}/rescan", status_code=202)
    def rescan(scan_id: str, background: BackgroundTasks) -> ScanStatus:
        """Re-run a GitHub scan (after pushing fixes) and diff against the previous one."""
        with sm()() as s:
            prev = s.get(ScanRecord, scan_id)
            if prev is None:
                raise HTTPException(404, "scan not found")
            if prev.source_type != "github":
                raise HTTPException(400, "rescan of a ZIP upload needs a new upload with baseline_id")
            new_id = uuid.uuid4().hex[:12]
            rec = ScanRecord(id=new_id, source_type="github", source_ref=prev.source_ref, packs=prev.packs,
                             answers_json=prev.answers_json, baseline_id=prev.id)
            s.add(rec)
            s.commit()
            status = _status(rec)
        if run_inline:
            run_job(sm(), new_id)
        else:
            background.add_task(run_job, sm(), new_id)
        return status

    @app.get("/api/scans")
    def list_scans(limit: int = 20) -> list[ScanStatus]:
        with sm()() as s:
            recs = s.scalars(select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(min(limit, 100))).all()
            return [_status(r) for r in recs]

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str) -> ScanStatus:
        with sm()() as s:
            rec = s.get(ScanRecord, scan_id)
            if rec is None:
                raise HTTPException(404, "scan not found")
            return _status(rec)

    def _result_or_404(scan_id: str):
        res = load_result(sm(), scan_id)
        if res is None:
            raise HTTPException(404, "report not ready")
        return res

    @app.get("/api/scans/{scan_id}/report.json")
    def report_json(scan_id: str) -> Response:
        return JSONResponse(json.loads(_result_or_404(scan_id).model_dump_json()))

    @app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
    def report_html(scan_id: str, download: bool = False) -> HTMLResponse:
        headers = {"Content-Disposition": f'attachment; filename="privtrace-{scan_id}.html"'} if download else {}
        return HTMLResponse(render_html(_result_or_404(scan_id)), headers=headers)

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: str) -> Response:
        with sm()() as s:
            rec = s.get(ScanRecord, scan_id)
            if rec:
                s.delete(rec)
                s.commit()
        return Response(status_code=204)

    return app


app = create_app()
