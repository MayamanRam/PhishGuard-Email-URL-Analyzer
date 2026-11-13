"""DKIM DNS Record Model for Air-Gapped Verification Cache."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def generate_dkim_record_id() -> str:
    return f"dkim_rec_{uuid.uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DkimDnsRecord(Base):
    """Cached DNS TXT record for offline DKIM cryptographic verification."""

    __tablename__ = "dkim_dns_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_dkim_record_id)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    selector: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key_txt: Mapped[str] = mapped_column(Text, nullable=False)
    source_snapshot: Mapped[str] = mapped_column(String(255), nullable=False, default="manual_import")
    imported_at: Mapped[str] = mapped_column(String(32), nullable=False, default=utc_now_iso)
    notes: Mapped[str] = mapped_column(Text, nullable=True, default="")

    __table_args__ = (
        Index("idx_dkim_domain_selector", "domain", "selector", unique=True),
        Index("idx_dkim_domain", "domain"),
    )

