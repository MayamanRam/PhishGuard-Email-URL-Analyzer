"""Database Seeding Utility for Detection Rules Catalog."""

from sqlalchemy.orm import Session

from app.detection.catalog import RULE_CATALOG
from app.models.detection_rule import DetectionRule


def seed_detection_rules(db: Session) -> int:
    """Seed the 24 deterministic detection rules into SQLite if not present."""
    count = 0
    for rule_def in RULE_CATALOG.values():
        existing = db.get(DetectionRule, rule_def.rule_id)
        if not existing:
            rule = DetectionRule(
                id=rule_def.rule_id,
                name=rule_def.rule_name,
                category=rule_def.category,
                severity=rule_def.severity.upper(),
                risk_weight=int(rule_def.base_weight),
                confidence=rule_def.confidence_multiplier,
                description=rule_def.description,
                remediation=rule_def.remediation_advice,
                version="1.0.0",
                enabled=1,
            )
            db.add(rule)
            count += 1

    if count > 0:
        db.commit()
    return count

