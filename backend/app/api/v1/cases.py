"""Investigation Cases and Incident Response Endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.case import ArtifactAssociateRequest, CaseCreateRequest, CaseUpdateRequest, NoteCreateRequest
from app.services.case_service import CaseService

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Create a new security investigation case."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    case = CaseService.create_case(
        db=db,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        assigned_to=payload.assigned_to,
        actor="analyst",
        ip_address=client_ip,
    )
    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status.lower(),
        "severity": case.severity.lower(),
        "created_at": case.created_at,
    }


@router.get("", status_code=status.HTTP_200_OK)
def list_cases(
    status_filter: str | None = Query(None, alias="status"),
    severity_filter: str | None = Query(None, alias="severity"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List investigation cases with filtering and pagination."""
    items, total = CaseService.list_cases(
        db=db,
        status=status_filter,
        severity=severity_filter,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [
            {
                "id": c.id,
                "case_number": c.case_number,
                "title": c.title,
                "description": c.resolution_summary,
                "status": c.status.lower(),
                "severity": c.severity.lower(),
                "classification": c.classification,
                "created_at": c.created_at,
                "updated_at": c.updated_at,
            }
            for c in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{case_id}", status_code=status.HTTP_200_OK)
def get_case(case_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Get full case details including timeline notes and linked artifacts."""
    case = CaseService.get_case(db, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.resolution_summary,
        "status": case.status.lower(),
        "severity": case.severity.lower(),
        "classification": case.classification,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "notes": [
            {
                "id": n.id,
                "author": n.author,
                "content": n.note_text,
                "created_at": n.created_at,
            }
            for n in (case.notes or [])
        ],
        "artifacts": [
            {
                "id": a.id,
                "case_id": a.case_id,
                "artifact_id": a.analysis_id,
                "associated_at": a.associated_at,
            }
            for a in (case.artifact_associations or [])
        ],
    }


@router.patch("/{case_id}", status_code=status.HTTP_200_OK)
def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Update case status, severity, or classification."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    updated = CaseService.update_case(
        db=db,
        case_id=case_id,
        status=payload.status,
        severity=payload.severity,
        assigned_to=payload.assigned_to,
        actor="analyst",
        ip_address=client_ip,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {
        "id": updated.id,
        "case_number": updated.case_number,
        "status": updated.status.lower(),
        "severity": updated.severity.lower(),
        "updated_at": updated.updated_at,
    }


@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
def add_case_note(
    case_id: str,
    payload: NoteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Append an analyst note to a case."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    note = CaseService.add_note(
        db=db,
        case_id=case_id,
        content=payload.content,
        author=payload.author,
        ip_address=client_ip,
    )
    if not note:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {
        "id": note.id,
        "author": note.author,
        "content": note.note_text,
        "created_at": note.created_at,
    }


@router.post("/{case_id}/artifacts", status_code=status.HTTP_201_CREATED)
def link_artifact_to_case(
    case_id: str,
    payload: ArtifactAssociateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Link an artifact to an investigation case."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    assoc = CaseService.associate_artifact(
        db=db,
        case_id=case_id,
        artifact_type=payload.artifact_type,
        artifact_id=payload.artifact_id,
        actor="analyst",
        ip_address=client_ip,
    )
    if not assoc:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {
        "id": assoc.id,
        "case_id": assoc.case_id,
        "analysis_id": assoc.analysis_id,
        "associated_at": assoc.associated_at,
    }
