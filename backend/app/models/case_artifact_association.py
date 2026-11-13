"""Association table linking Investigation Cases with Analysis Runs."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_assoc_id() -> str:
    return f"assoc_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseArtifactAssociation(Base):
    """Associates an analysis run with an investigation case."""

    __tablename__ = "case_artifact_associations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_assoc_id)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False
    )
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    associated_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)

    # Relationships
    investigation_case = relationship("InvestigationCase", back_populates="artifact_associations")
    analysis_run = relationship("AnalysisRun", back_populates="case_associations")

    __table_args__ = (
        UniqueConstraint("case_id", "analysis_id", name="uq_case_analysis"),
        Index("idx_assoc_case", "case_id"),
        Index("idx_assoc_run", "analysis_id"),
    )
