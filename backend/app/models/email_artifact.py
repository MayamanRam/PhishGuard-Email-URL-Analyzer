"""Email Artifact Model representing ingested RFC 5322 metadata and structure."""

from datetime import datetime, timezone
from typing import Optional
import uuid
from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_email_id() -> str:
    return f"eml_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EmailArtifact(Base):
    """Immutable record of an ingested email's extracted headers and structure."""

    __tablename__ = "email_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_email_id)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    evidence_file_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    message_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False, default="")
    from_header: Mapped[str] = mapped_column(Text, nullable=False, default="")
    from_address: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    from_domain: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    from_display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reply_to_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    return_path_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    sender_address: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    date_header: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    auth_results_raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Serialized JSON of auth claims
    routing_hops_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # Serialized JSON of Received hops
    body_plain_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    body_html_length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attachment_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    url_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    submitted_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    is_immutable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationship
    analysis_run = relationship("AnalysisRun", back_populates="email_artifact")

    __table_args__ = (
        Index("idx_eml_analysis_id", "analysis_id"),
        Index("idx_eml_sha256", "sha256_hash"),
        Index("idx_eml_from_domain", "from_domain"),
    )
