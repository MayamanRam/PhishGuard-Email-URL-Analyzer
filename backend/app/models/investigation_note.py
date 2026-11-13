"""Investigation Note Model representing analyst comments and updates on a case."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def generate_note_id() -> str:
    return f"note_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InvestigationNote(Base):
    """Editable analyst note attached to an investigation case."""

    __tablename__ = "investigation_notes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_note_id)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst")
    note_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    updated_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso, onupdate=utc_now_iso)

    # Relationship
    investigation_case = relationship("InvestigationCase", back_populates="notes")

    __table_args__ = (
        Index("idx_notes_case_id", "case_id"),
        Index("idx_notes_created_at", "created_at"),
    )
