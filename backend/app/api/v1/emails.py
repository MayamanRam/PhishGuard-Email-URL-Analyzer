"""Email Threat Analysis Endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database.session import get_db
from app.models import AnalysisRun
from app.schemas.email import EmailAnalyzeTextRequest
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/emails", tags=["Emails"])
analysis_service = AnalysisService()


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_email_upload(
    request: Request,
    file: UploadFile = File(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Analyze an uploaded .eml email file."""
    if not file:
        raise HTTPException(status_code=400, detail="No email file provided.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded email file is empty.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        result = analysis_service.analyze_email(
            db=db,
            raw_email_bytes=content,
            source_filename=file.filename or "uploaded.eml",
            actor="analyst",
            ip_address=client_ip,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze email: {str(e)}")


@router.post("/analyze-text", status_code=status.HTTP_200_OK)
def analyze_email_text(
    payload: EmailAnalyzeTextRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Analyze pasted raw RFC 5322 email text."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        raw_bytes = payload.raw_email.encode("utf-8", errors="replace")
        result = analysis_service.analyze_email(
            db=db,
            raw_email_bytes=raw_bytes,
            source_filename=payload.source_name,
            actor="analyst",
            ip_address=client_ip,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze email text: {str(e)}")


@router.get("/{run_id}", status_code=status.HTTP_200_OK)
def get_email_analysis(run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve details of a previous email analysis run."""
    stmt = (
        select(AnalysisRun)
        .where(AnalysisRun.id == run_id)
        .options(
            selectinload(AnalysisRun.findings),
            selectinload(AnalysisRun.email_artifact),
            selectinload(AnalysisRun.url_artifacts),
            selectinload(AnalysisRun.attachment_artifacts),
        )
    )
    run = db.scalar(stmt)
    if not run:
        raise HTTPException(status_code=404, detail="Email analysis run not found.")

    email_art = run.email_artifact
    summary_data = {}
    if isinstance(run.summary, str):
        try:
            summary_data = json.loads(run.summary)
        except (json.JSONDecodeError, TypeError):
            summary_data = {"raw_summary": run.summary}

    return {
        "run_id": run.id,
        "target_type": run.artifact_type.lower(),
        "target_identifier": summary_data.get("target", run.id),
        "risk_score": run.risk_score,
        "severity": run.risk_level.lower(),
        "created_at": run.created_at,
        "summary": summary_data,
        "email_artifact": {
            "id": email_art.id,
            "subject": email_art.subject,
            "from_address": email_art.from_address,
            "from_display_name": email_art.from_display_name,
            "from_domain": email_art.from_domain,
            "reply_to": email_art.reply_to_address,
            "return_path": email_art.return_path_address,
            "date": email_art.date_header,
            "sha256": email_art.sha256_hash,
            "routing_hops": json.loads(email_art.routing_hops_json) if email_art.routing_hops_json else [],
            "auth_claims": json.loads(email_art.auth_results_raw) if email_art.auth_results_raw else {},
        } if email_art else None,
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.lower(),
                "confidence": f.confidence,
                "remediation": f.recommended_action,
                "evidence": json.loads(f.evidence_details) if f.evidence_details else {},
            }
            for f in run.findings
        ],
        "urls": [
            {
                "id": u.id,
                "url": u.normalized_url,
                "hostname": u.hostname,
                "domain": u.registered_domain,
                "is_ip": bool(u.is_ip_host),
                "is_punycode": bool(u.has_punycode),
            }
            for u in run.url_artifacts
        ],
        "attachments": [
            {
                "id": a.id,
                "filename": a.filename,
                "mime_type": a.reported_mime_type,
                "extension": a.detected_extension,
                "is_executable": bool(a.is_executable_type),
                "is_archive": bool(a.is_archive_type),
                "size_bytes": a.file_size_bytes,
                "sha256": a.sha256_hash,
            }
            for a in run.attachment_artifacts
        ],
    }
