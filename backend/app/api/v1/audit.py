"""Audit Log Retrieval Endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import AuditEvent
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("", status_code=status.HTTP_200_OK)
def list_audit_events(
    action: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List append-only audit trail events."""
    count_stmt = select(func.count(AuditEvent.id))
    if action:
        count_stmt = count_stmt.where(AuditEvent.event_type == action)
    total = db.scalar(count_stmt) or 0

    events = AuditService.list_events(db, limit=limit, offset=offset, action_filter=action)

    return {
        "items": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "object_type": e.object_type,
                "object_id": e.object_id,
                "status": e.status,
                "details": json.loads(e.details_json) if e.details_json else {},
                "client_ip": e.client_ip,
                "timestamp": e.timestamp,
            }
            for e in events
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
