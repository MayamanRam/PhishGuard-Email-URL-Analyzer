"""Detection Rule Model for the deterministic phishing indicator rule catalog."""

from sqlalchemy import Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


class DetectionRule(Base):
    """Catalog of versioned deterministic detection rules."""

    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g., 'HDR-001', 'URL-002'
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)  # 'HEADER', 'AUTH', 'URL', 'DOMAIN', 'CONTENT', 'ATTACHMENT'
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    risk_weight: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")
    enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Relationships
    findings = relationship("Finding", back_populates="rule")

    __table_args__ = (
        Index("idx_rules_category", "category"),
        Index("idx_rules_severity", "severity"),
    )
