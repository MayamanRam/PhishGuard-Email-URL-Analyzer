"""Air-Gapped DKIM DNS Cache Management Endpoints."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.dkim_dns_record import DkimDnsRecord
from app.schemas.dkim import DkimRecordResponse, DkimSnapshotImportRequest
from app.services.audit_service import AuditService

router = APIRouter(prefix="/dkim-cache", tags=["DKIM DNS Cache"])


@router.post("/import", status_code=status.HTTP_200_OK)
def import_dkim_snapshot(
    payload: DkimSnapshotImportRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Import an offline DNS TXT zone snapshot for air-gapped DKIM verification."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    imported_count = 0
    updated_count = 0

    for item in payload.records:
        domain_clean = item.domain.strip().lower()
        selector_clean = item.selector.strip().lower()

        # Check existing record
        stmt = select(DkimDnsRecord).where(
            DkimDnsRecord.domain == domain_clean,
            DkimDnsRecord.selector == selector_clean,
        )
        existing = db.scalar(stmt)

        if existing:
            existing.public_key_txt = item.public_key_txt.strip()
            existing.source_snapshot = payload.source_snapshot.strip()
            existing.notes = item.notes or existing.notes
            updated_count += 1
        else:
            new_record = DkimDnsRecord(
                domain=domain_clean,
                selector=selector_clean,
                public_key_txt=item.public_key_txt.strip(),
                source_snapshot=payload.source_snapshot.strip(),
                notes=item.notes or "",
            )
            db.add(new_record)
            imported_count += 1

    AuditService.log(
        db=db,
        action="DKIM_CACHE_IMPORTED",
        entity_type="DkimDnsRecord",
        entity_id=payload.source_snapshot,
        actor="analyst",
        ip_address=client_ip,
        metadata={
            "source_snapshot": payload.source_snapshot,
            "imported_count": imported_count,
            "updated_count": updated_count,
            "total_records": len(payload.records),
        },
    )

    db.commit()

    return {
        "status": "success",
        "message": f"Successfully processed {len(payload.records)} DKIM DNS records.",
        "imported": imported_count,
        "updated": updated_count,
        "source_snapshot": payload.source_snapshot,
    }


@router.get("", status_code=status.HTTP_200_OK)
def list_dkim_records(
    domain: str | None = Query(None, description="Optional domain filter"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List cached DKIM DNS records available for air-gapped verification."""
    query = select(DkimDnsRecord)
    if domain:
        query = query.where(DkimDnsRecord.domain.ilike(f"%{domain.strip().lower()}%"))

    count_stmt = select(func.count(DkimDnsRecord.id))
    if domain:
        count_stmt = count_stmt.where(DkimDnsRecord.domain.ilike(f"%{domain.strip().lower()}%"))
    total = db.scalar(count_stmt) or 0

    items_stmt = query.order_by(desc(DkimDnsRecord.imported_at)).offset(offset).limit(limit)
    records = list(db.scalars(items_stmt).all())

    return {
        "items": [
            {
                "id": r.id,
                "domain": r.domain,
                "selector": r.selector,
                "public_key_txt": r.public_key_txt,
                "source_snapshot": r.source_snapshot,
                "imported_at": r.imported_at,
                "notes": r.notes,
            }
            for r in records
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.delete("/{record_id}", status_code=status.HTTP_200_OK)
def delete_dkim_record(
    record_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Delete a cached DKIM DNS record."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    stmt = select(DkimDnsRecord).where(DkimDnsRecord.id == record_id)
    record = db.scalar(stmt)
    if not record:
        raise HTTPException(status_code=404, detail="DKIM record not found")

    domain = record.domain
    selector = record.selector

    db.delete(record)
    AuditService.log(
        db=db,
        action="DKIM_RECORD_DELETED",
        entity_type="DkimDnsRecord",
        entity_id=record_id,
        actor="analyst",
        ip_address=client_ip,
        metadata={"domain": domain, "selector": selector},
    )
    db.commit()

    return {
        "status": "success",
        "message": f"Deleted DKIM record for {selector}._domainkey.{domain}",
    }

