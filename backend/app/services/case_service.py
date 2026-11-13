"""Investigation Case Management Service.

Coordinates incident response cases, analyst notes, and artifact associations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app.models import CaseArtifactAssociation, InvestigationCase, InvestigationNote
from app.services.audit_service import AuditService


class CaseService:
    """Service handling case management workflows."""

    @staticmethod
    def create_case(
        db: Session,
        title: str,
        description: str | None = None,
        severity: str = "medium",
        assigned_to: str | None = None,
        actor: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> InvestigationCase:
        """Create a new investigation case."""
        case_id = f"case_{uuid.uuid4().hex}"
        case_num = f"PG-CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        case = InvestigationCase(
            id=case_id,
            case_number=case_num,
            title=title.strip(),
            status="OPEN",
            severity=severity.upper(),
            classification="UNCLASSIFIED",
            resolution_summary=description or "",
            created_at=now_iso,
            updated_at=now_iso,
        )
        db.add(case)
        db.flush()

        AuditService.log(
            db=db,
            action="CASE_CREATED",
            entity_type="InvestigationCase",
            entity_id=case_id,
            actor=actor,
            ip_address=ip_address,
            metadata={"title": case.title, "severity": case.severity, "case_number": case.case_number},
        )
        db.commit()
        db.refresh(case)
        return case

    @staticmethod
    def get_case(db: Session, case_id: str) -> InvestigationCase | None:
        """Get case by ID with associated notes and artifact links."""
        stmt = (
            select(InvestigationCase)
            .where(InvestigationCase.id == case_id)
            .options(
                selectinload(InvestigationCase.notes),
                selectinload(InvestigationCase.artifact_associations),
            )
        )
        return db.scalar(stmt)

    @staticmethod
    def list_cases(
        db: Session,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[InvestigationCase], int]:
        """List cases with optional filters and total count."""
        base_stmt = select(InvestigationCase)
        count_stmt = select(func.count(InvestigationCase.id))

        if status:
            base_stmt = base_stmt.where(InvestigationCase.status == status.upper())
            count_stmt = count_stmt.where(InvestigationCase.status == status.upper())
        if severity:
            base_stmt = base_stmt.where(InvestigationCase.severity == severity.upper())
            count_stmt = count_stmt.where(InvestigationCase.severity == severity.upper())

        total = db.scalar(count_stmt) or 0
        items = list(
            db.scalars(
                base_stmt.order_by(desc(InvestigationCase.updated_at)).offset(offset).limit(limit)
            ).all()
        )
        return items, total

    @staticmethod
    def update_case(
        db: Session,
        case_id: str,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        actor: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> InvestigationCase | None:
        """Update case status, severity, or classification."""
        case = CaseService.get_case(db, case_id)
        if not case:
            return None

        changes: dict[str, Any] = {}
        if status and status.upper() != case.status:
            changes["old_status"] = case.status
            changes["new_status"] = status.upper()
            case.status = status.upper()

        if severity and severity.upper() != case.severity:
            changes["old_severity"] = case.severity
            changes["new_severity"] = severity.upper()
            case.severity = severity.upper()

        if changes:
            case.updated_at = datetime.now(timezone.utc).isoformat()
            AuditService.log(
                db=db,
                action="CASE_UPDATED",
                entity_type="InvestigationCase",
                entity_id=case.id,
                actor=actor,
                ip_address=ip_address,
                metadata=changes,
            )
            db.commit()
            db.refresh(case)

        return case

    @staticmethod
    def add_note(
        db: Session,
        case_id: str,
        content: str,
        author: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> InvestigationNote | None:
        """Append an analyst note to a case."""
        case = CaseService.get_case(db, case_id)
        if not case:
            return None

        note_id = f"note_{uuid.uuid4().hex}"
        now_iso = datetime.now(timezone.utc).isoformat()
        note = InvestigationNote(
            id=note_id,
            case_id=case.id,
            author=author,
            note_text=content.strip(),
            created_at=now_iso,
            updated_at=now_iso,
        )
        db.add(note)
        case.updated_at = now_iso

        AuditService.log(
            db=db,
            action="NOTE_ADDED",
            entity_type="InvestigationNote",
            entity_id=note_id,
            actor=author,
            ip_address=ip_address,
            metadata={"case_id": case.id},
        )
        db.commit()
        db.refresh(note)
        return note

    @staticmethod
    def associate_artifact(
        db: Session,
        case_id: str,
        artifact_type: str,
        artifact_id: str,
        actor: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> CaseArtifactAssociation | None:
        """Link an analysis run to an investigation case."""
        case = CaseService.get_case(db, case_id)
        if not case:
            return None

        assoc_id = f"assoc_{uuid.uuid4().hex}"
        assoc = CaseArtifactAssociation(
            id=assoc_id,
            case_id=case.id,
            analysis_id=artifact_id,
            associated_at=datetime.now(timezone.utc).isoformat(),
        )
        db.add(assoc)
        case.updated_at = datetime.now(timezone.utc).isoformat()

        AuditService.log(
            db=db,
            action="ARTIFACT_ASSOCIATED",
            entity_type="CaseArtifactAssociation",
            entity_id=assoc_id,
            actor=actor,
            ip_address=ip_address,
            metadata={"case_id": case.id, "analysis_id": artifact_id},
        )
        db.commit()
        db.refresh(assoc)
        return assoc
