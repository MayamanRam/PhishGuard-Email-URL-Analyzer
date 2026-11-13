"""Investigation Case Model for managing analyst incident workflows."""

from datetime import datetime, timezone
from typing import List, Optional
import uuid
from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_case_id() -> str:
    return f"case_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InvestigationCase(Base):
    """Editable incident response investigation case record."""

    __tablename__ = "investigation_cases"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_case_id)
    case_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)  # e.g. 'PG-CASE-2026-0001'
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")  # 'OPEN', 'IN_REVIEW', 'ESCALATED', 'RESOLVED', 'CLOSED'
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNCLASSIFIED"
    )  # 'TRUE_POSITIVE_PHISH', 'BENIGN_FALSE_POSITIVE', 'SUSPICIOUS_NEEDS_MONITORING', 'SPAM_MARKETING', 'UNCLASSIFIED'
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso, onupdate=utc_now_iso)

    # Relationships
    artifact_associations: Mapped[List["CaseArtifactAssociation"]] = relationship(
        "CaseArtifactAssociation", back_populates="investigation_case", cascade="all, delete-orphan"
    )
    notes: Mapped[List["InvestigationNote"]] = relationship(
        "InvestigationNote", back_populates="investigation_case", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_cases_status", "status"),
        Index("idx_cases_number", "case_number"),
        Index("idx_cases_classification", "classification"),
    )
