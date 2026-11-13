"""Report Model representing generated PDF, CSV, and JSON exports."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def generate_report_id() -> str:
    return f"rep_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Report(Base):
    """Immutable record of an exported PDF, CSV, or JSON investigation report."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_report_id)
    report_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)  # e.g., 'PG-REP-2026-0001'
    report_type: Mapped[str] = mapped_column(String(16), nullable=False)  # 'ANALYSIS' or 'CASE'
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)  # references analysis_runs.id or investigation_cases.id
    format: Mapped[str] = mapped_column(String(8), nullable=False)  # 'PDF', 'CSV', 'JSON'
    file_path: Mapped[str] = mapped_column(String(255), nullable=False)
    file_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst")
    created_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)

    __table_args__ = (
        Index("idx_rep_target", "target_id"),
        Index("idx_rep_type", "report_type"),
        Index("idx_rep_number", "report_number"),
    )
