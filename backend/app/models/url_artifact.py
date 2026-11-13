"""URL Artifact Model representing extracted or directly analyzed URL strings."""

from datetime import datetime, timezone
from typing import Optional
import uuid
from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_url_id() -> str:
    return f"url_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UrlArtifact(Base):
    """Immutable record of an extracted or submitted URL and its static metrics."""

    __tablename__ = "url_artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_url_id)
    analysis_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    original_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    registered_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    public_suffix: Mapped[str] = mapped_column(String(128), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="/")
    query_string: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_ip_host: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_punycode: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    has_userinfo: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    redirect_param_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    display_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    text_destination_mismatch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    detected_brands_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Serialized JSON list of brands
    submitted_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    is_immutable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationship
    analysis_run = relationship("AnalysisRun", back_populates="url_artifacts")

    __table_args__ = (
        Index("idx_url_analysis_id", "analysis_id"),
        Index("idx_url_hostname", "hostname"),
        Index("idx_url_reg_domain", "registered_domain"),
    )
