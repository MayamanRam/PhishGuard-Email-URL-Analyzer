"""Audit Event Model for immutable security event logging."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def generate_audit_id() -> str:
    return f"aud_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditEvent(Base):
    """Append-only audit trail logging significant application operations."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_audit_id)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    object_type: Mapped[str] = mapped_column(String(32), nullable=False)
    object_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="SUCCESS")  # 'SUCCESS', 'FAILED', 'WARNING'
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    client_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="127.0.0.1")
    timestamp: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_object", "object_type", "object_id"),
    )
