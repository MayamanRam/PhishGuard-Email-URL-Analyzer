"""Static URL Threat Analysis Endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.database.session import get_db
from app.models import AnalysisRun
from app.schemas.email import UrlAnalyzeRequest
from app.services.analysis_service import AnalysisService

router = APIRouter(prefix="/urls", tags=["URLs"])
analysis_service = AnalysisService()


@router.post("/analyze", status_code=status.HTTP_200_OK)
def analyze_url_endpoint(
    payload: UrlAnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Execute static threat analysis on a target URL."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        result = analysis_service.analyze_url(
            db=db,
            raw_url=payload.url,
            actor="analyst",
            ip_address=client_ip,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze URL: {str(e)}")


@router.get("/{run_id}", status_code=status.HTTP_200_OK)
def get_url_analysis(run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve details of a previous URL analysis run."""
    stmt = (
        select(AnalysisRun)
        .where(AnalysisRun.id == run_id)
        .options(
            selectinload(AnalysisRun.findings),
            selectinload(AnalysisRun.url_artifacts),
        )
    )
    run = db.scalar(stmt)
    if not run:
        raise HTTPException(status_code=404, detail="URL analysis run not found.")

    url_art = run.url_artifacts[0] if run.url_artifacts else None
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
        "url_artifact": {
            "id": url_art.id,
            "original_url": url_art.original_url,
            "normalized_url": url_art.normalized_url,
            "hostname": url_art.hostname,
            "registered_domain": url_art.registered_domain,
            "is_ip_host": bool(url_art.is_ip_host),
            "has_punycode": bool(url_art.has_punycode),
        } if url_art else None,
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
    }
