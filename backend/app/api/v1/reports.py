"""Report Generation and Retrieval Endpoints."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Report
from app.reports.generator import ReportGeneratorService
from app.schemas.report import ReportCreateRequest
from app.services.audit_service import AuditService

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("", status_code=status.HTTP_201_CREATED)
def generate_report(
    payload: ReportCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Generate a new threat analysis report (JSON, CSV, or PDF)."""
    if not payload.analysis_run_id and not payload.case_id:
        raise HTTPException(status_code=400, detail="Must provide either analysis_run_id or case_id.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        report = ReportGeneratorService.generate_report(
            db=db,
            format_type=payload.format,
            analysis_run_id=payload.analysis_run_id,
            case_id=payload.case_id,
            actor="analyst",
            ip_address=client_ip,
        )
        return {
            "id": report.id,
            "report_number": report.report_number,
            "report_type": report.report_type,
            "format": report.format.lower(),
            "sha256_hash": report.file_hash_sha256,
            "file_size_bytes": report.file_size_bytes,
            "created_at": report.created_at,
            "download_url": f"/api/v1/reports/{report.id}/download",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


@router.get("", status_code=status.HTTP_200_OK)
def list_reports(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List previously generated reports."""
    count_stmt = select(func.count(Report.id))
    total = db.scalar(count_stmt) or 0

    items_stmt = select(Report).order_by(desc(Report.created_at)).offset(offset).limit(limit)
    items = list(db.scalars(items_stmt).all())

    return {
        "items": [
            {
                "id": r.id,
                "report_number": r.report_number,
                "report_type": r.report_type,
                "target_id": r.target_id,
                "format": r.format.lower(),
                "sha256_hash": r.file_hash_sha256,
                "file_size_bytes": r.file_size_bytes,
                "generated_by": r.generated_by,
                "created_at": r.created_at,
                "download_url": f"/api/v1/reports/{r.id}/download",
            }
            for r in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download a generated report with path-traversal protection."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        file_path, filename = ReportGeneratorService.get_report_file(db, report_id)

        AuditService.log(
            db=db,
            action="REPORT_DOWNLOADED",
            entity_type="Report",
            entity_id=report_id,
            actor="analyst",
            ip_address=client_ip,
        )
        db.commit()

        media_types = {
            "json": "application/json",
            "csv": "text/csv",
            "pdf": "application/pdf",
            "stix": "application/stix+json;version=2.1",
        }
        stmt = select(Report).where(Report.id == report_id)
        rep_record = db.scalar(stmt)
        fmt = rep_record.format.lower() if rep_record else filename.split(".")[-1].lower()
        media_type = media_types.get(fmt, "application/octet-stream")

        return FileResponse(
            path=file_path,
            filename=filename,
            media_type=media_type,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")
