"""Attachment Artifact Model representing extracted email attachment metadata."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_att_id() -> str:
    return f"att_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttachmentArtifact(Base):
    """Immutable forensic metadata record for an email attachment."""

    __tablename__ = "attachment_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_att_id)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    reported_mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    detected_extension: Mapped[str] = mapped_column(String(32), nullable=False)
    has_double_extension: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_executable_type: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_archive_type: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    submitted_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    is_immutable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationship
    analysis_run = relationship("AnalysisRun", back_populates="attachment_artifacts")

    __table_args__ = (
        Index("idx_att_analysis_id", "analysis_id"),
        Index("idx_att_sha256", "sha256_hash"),
    )
