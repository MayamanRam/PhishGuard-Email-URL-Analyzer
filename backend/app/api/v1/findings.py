"""Findings and Rule Catalog Endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.detection.catalog import RULE_CATALOG
from app.models import Finding

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", status_code=status.HTTP_200_OK)
def list_findings(
    severity: str | None = Query(None),
    category: str | None = Query(None),
    run_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List security findings across analysis runs with filtering."""
    base_stmt = select(Finding)
    count_stmt = select(func.count(Finding.id))

    if severity:
        base_stmt = base_stmt.where(Finding.severity == severity.upper())
        count_stmt = count_stmt.where(Finding.severity == severity.upper())
    if category:
        base_stmt = base_stmt.where(Finding.category == category.upper())
        count_stmt = count_stmt.where(Finding.category == category.upper())
    if run_id:
        base_stmt = base_stmt.where(Finding.analysis_id == run_id)
        count_stmt = count_stmt.where(Finding.analysis_id == run_id)

    total = db.scalar(count_stmt) or 0
    items = list(
        db.scalars(base_stmt.order_by(desc(Finding.created_at)).offset(offset).limit(limit)).all()
    )

    return {
        "items": [
            {
                "id": f.id,
                "analysis_id": f.analysis_id,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.lower(),
                "confidence": f.confidence,
                "recommended_action": f.recommended_action,
                "evidence_details": json.loads(f.evidence_details) if f.evidence_details else {},
                "created_at": f.created_at,
            }
            for f in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/rules", status_code=status.HTTP_200_OK)
def list_rule_catalog() -> list[dict[str, Any]]:
    """Return the complete catalog of deterministic detection rules."""
    return [
        {
            "rule_id": r.rule_id,
            "rule_name": r.rule_name,
            "category": r.category,
            "severity": r.severity,
            "base_weight": r.base_weight,
            "confidence_multiplier": r.confidence_multiplier,
            "description": r.description,
            "remediation_advice": r.remediation_advice,
            "mitre_attack_id": r.mitre_attack_id,
        }
        for r in RULE_CATALOG.values()
    ]
