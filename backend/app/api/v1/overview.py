"""Overview and SOC Dashboard Analytics Endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import AnalysisRun, Finding, InvestigationCase

router = APIRouter(prefix="/overview", tags=["Overview"])


@router.get("/stats", status_code=status.HTTP_200_OK)
def get_dashboard_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve operational dashboard summary metrics for SOC view."""
    total_runs = db.scalar(select(func.count(AnalysisRun.id))) or 0
    email_runs = (
        db.scalar(select(func.count(AnalysisRun.id)).where(AnalysisRun.artifact_type == "EMAIL")) or 0
    )
    url_runs = (
        db.scalar(select(func.count(AnalysisRun.id)).where(AnalysisRun.artifact_type == "URL")) or 0
    )

    open_cases = (
        db.scalar(
            select(func.count(InvestigationCase.id)).where(
                InvestigationCase.status.in_(["OPEN", "IN_REVIEW", "ESCALATED"])
            )
        )
        or 0
    )
    total_findings = db.scalar(select(func.count(Finding.id))) or 0

    # Severity distribution across all runs
    sev_counts: dict[str, int] = {"low": 0, "moderate": 0, "high": 0, "critical": 0}
    sev_rows = db.execute(
        select(AnalysisRun.risk_level, func.count(AnalysisRun.id)).group_by(AnalysisRun.risk_level)
    ).all()
    for sev_level, count in sev_rows:
        key = str(sev_level or "").lower()
        if key in sev_counts:
            sev_counts[key] = count

    # 5 most recent runs
    recent_runs = list(
        db.scalars(
            select(AnalysisRun).order_by(desc(AnalysisRun.created_at)).limit(5)
        ).all()
    )

    recent_list = []
    for r in recent_runs:
        target = r.id
        if isinstance(r.summary, str):
            try:
                parsed_summary = json.loads(r.summary)
                target = parsed_summary.get("target", r.id)
            except (json.JSONDecodeError, TypeError):
                target = r.id

        recent_list.append({
            "id": r.id,
            "target_type": r.artifact_type.lower(),
            "target_identifier": target,
            "risk_score": r.risk_score,
            "severity": r.risk_level.lower(),
            "created_at": r.created_at,
        })

    return {
        "total_analyses": total_runs,
        "email_analyses": email_runs,
        "url_analyses": url_runs,
        "open_cases": open_cases,
        "total_findings": total_findings,
        "severity_distribution": sev_counts,
        "recent_analyses": recent_list,
    }
