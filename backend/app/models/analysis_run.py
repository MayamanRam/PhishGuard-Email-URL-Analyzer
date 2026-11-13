"""Analysis Run Model representing an email or URL threat assessment execution."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_run_id() -> str:
    return f"run_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnalysisRun(Base):
    """Immutable record of an automated phishing threat analysis run."""

    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_run_id)
    artifact_type: Mapped[str] = mapped_column(String(16), nullable=False)  # 'EMAIL' or 'URL'
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 to 100
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)  # 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_time_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    is_immutable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    email_artifact = relationship(
        "EmailArtifact", back_populates="analysis_run", uselist=False, cascade="all, delete-orphan"
    )
    url_artifacts = relationship(
        "UrlArtifact", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    attachment_artifacts = relationship(
        "AttachmentArtifact", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    findings = relationship(
        "Finding", back_populates="analysis_run", cascade="all, delete-orphan"
    )
    case_associations = relationship(
        "CaseArtifactAssociation", back_populates="analysis_run", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_runs_created_at", "created_at"),
        Index("idx_runs_artifact_type", "artifact_type"),
        Index("idx_runs_risk_level", "risk_level"),
        Index("idx_runs_sha256", "sha256_hash"),
    )
