"""Append-Only Audit Logging Service.

Maintains an immutable audit log of all security evaluations, case mutations,
and report generation operations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models import AuditEvent


class AuditService:
    """Service for recording and querying audit trail events."""

    @staticmethod
    def log(
        db: Session,
        action: str,
        entity_type: str,
        entity_id: str | None = None,
        actor: str = "analyst",
        ip_address: str | None = "127.0.0.1",
        metadata: dict[str, Any] | None = None,
        status: str = "SUCCESS",
    ) -> AuditEvent:
        """Create an append-only audit event record."""
        event = AuditEvent(
            id=f"aud_{uuid.uuid4().hex}",
            event_type=action,
            object_type=entity_type,
            object_id=entity_id or "N/A",
            status=status.upper(),
            details_json=json.dumps(metadata or {}),
            client_ip=ip_address or "127.0.0.1",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        db.add(event)
        db.flush()
        return event

    @staticmethod
    def list_events(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        action_filter: str | None = None,
    ) -> list[AuditEvent]:
        """Query audit log entries ordered by timestamp descending."""
        stmt = select(AuditEvent).order_by(desc(AuditEvent.timestamp)).offset(offset).limit(limit)
        if action_filter:
            stmt = stmt.where(AuditEvent.event_type == action_filter)
        return list(db.scalars(stmt).all())
