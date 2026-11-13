"""Finding Model representing an indicator detected during an analysis run."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_finding_id() -> str:
    return f"fnd_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Finding(Base):
    """Immutable record of an observed detection rule match with supporting evidence."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_finding_id)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("detection_rules.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    evidence_details: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    is_immutable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    analysis_run = relationship("AnalysisRun", back_populates="findings")
    rule = relationship("DetectionRule", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_analysis_id", "analysis_id"),
        Index("idx_findings_rule_id", "rule_id"),
        Index("idx_findings_severity", "severity"),
    )
