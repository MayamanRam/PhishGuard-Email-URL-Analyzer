"""Report Generation and Archival Service.

Coordinates JSON, CSV, and PDF export generation, computes cryptographic hashes,
and enforces path traversal protection.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.detection.catalog import RULE_CATALOG
from app.models import AnalysisRun, InvestigationCase, Report
from app.reports.csv_exporter import CsvReportExporter
from app.reports.pdf_exporter import PdfReportExporter
from app.reports.stix_exporter import StixExporter
from app.services.audit_service import AuditService


class ReportGeneratorService:
    """Manages report compilation, hashing, and storage."""

    @classmethod
    def generate_report(
        cls,
        db: Session,
        format_type: str,  # json, csv, pdf
        analysis_run_id: str | None = None,
        case_id: str | None = None,
        actor: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> Report:
        """Generate and archive a threat analysis report."""
        format_lower = format_type.lower()
        if format_lower not in ("json", "csv", "pdf", "stix"):
            raise ValueError(f"Unsupported report format: '{format_type}'. Must be json, csv, pdf, or stix.")

        title = "PhishGuard Threat Analysis Report"
        target_id = "Unknown"
        risk_score = 0.0
        severity = "low"
        summary_text = ""
        category_scores: dict[str, float] = {}
        findings_data: list[dict[str, Any]] = []
        report_kind = "ANALYSIS"

        if analysis_run_id:
            run_stmt = (
                select(AnalysisRun)
                .where(AnalysisRun.id == analysis_run_id)
                .options(selectinload(AnalysisRun.findings))
            )
            run = db.scalar(run_stmt)
            if not run:
                raise ValueError(f"AnalysisRun not found: {analysis_run_id}")

            report_kind = "ANALYSIS"
            target_id = run.id
            risk_score = float(run.risk_score)
            severity = run.risk_level.lower()
            summary_info = {}
            if isinstance(run.summary, str):
                try:
                    summary_info = json.loads(run.summary)
                except (json.JSONDecodeError, TypeError):
                    summary_info = {}
            elif isinstance(run.summary, dict):
                summary_info = run.summary

            title = f"Threat Report: {summary_info.get('target', run.id)[:50]}"
            summary_text = summary_info.get("formula_explanation", f"Analysis completed with score {run.risk_score}")
            category_scores = summary_info.get("category_scores", {})
            findings_data = []
            for f in run.findings:
                rule_def = RULE_CATALOG.get(f.rule_id)
                findings_data.append({
                    "rule_id": f.rule_id,
                    "rule_name": f.title,
                    "category": f.category,
                    "severity": f.severity.lower(),
                    "base_weight": rule_def.base_weight if rule_def else 20.0,
                    "confidence_multiplier": f.confidence,
                    "effective_score": (rule_def.base_weight * f.confidence) if rule_def else 15.0,
                    "mitre_attack_id": rule_def.mitre_attack_id if rule_def else None,
                    "remediation_advice": f.recommended_action,
                    "evidence_data": json.loads(f.evidence_details) if isinstance(f.evidence_details, str) else {},
                })

        elif case_id:
            case_stmt = select(InvestigationCase).where(InvestigationCase.id == case_id)
            case = db.scalar(case_stmt)
            if not case:
                raise ValueError(f"InvestigationCase not found: {case_id}")
            report_kind = "CASE"
            target_id = case.id
            title = f"Case Report: {case.title}"
            severity = case.severity.lower()
            summary_text = case.resolution_summary or "Investigation case export."

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        report_id = f"rep_{uuid.uuid4().hex}"
        rep_num = f"PG-REP-{now.year}-{uuid.uuid4().hex[:6].upper()}"

        # Generate file bytes based on format
        if format_lower == "json":
            export_payload = {
                "report_id": report_id,
                "report_number": rep_num,
                "title": title,
                "target_id": target_id,
                "risk_score": risk_score,
                "severity": severity,
                "summary": summary_text,
                "category_scores": category_scores,
                "findings": findings_data,
                "generated_at": now_iso,
            }
            raw_bytes = json.dumps(export_payload, indent=2).encode("utf-8")
            extension = "json"
        elif format_lower == "csv":
            csv_str = CsvReportExporter.export_findings(findings_data)
            raw_bytes = csv_str.encode("utf-8")
            extension = "csv"
        elif format_lower == "pdf":
            raw_bytes = PdfReportExporter.generate_pdf(
                title=title,
                target_identifier=target_id,
                risk_score=risk_score,
                severity=severity,
                findings=findings_data,
                category_scores=category_scores,
                summary_text=summary_text,
                created_at=now.strftime("%Y-%m-%d %H:%M:%S"),
            )
            extension = "pdf"
        elif format_lower == "stix":
            stix_bundle_str = StixExporter.export_bundle(
                title=title,
                target_identifier=target_id,
                risk_score=risk_score,
                severity=severity,
                findings=findings_data,
                summary_text=summary_text,
                created_at=now_iso,
            )
            raw_bytes = stix_bundle_str.encode("utf-8")
            extension = "stix.json"
        else:
            raise ValueError(f"Unknown format: {format_lower}")

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        filename = f"report_{report_id}.{extension}"
        storage_path = os.path.join(str(settings.REPORTS_DIR), filename)
        os.makedirs(os.path.dirname(storage_path), exist_ok=True)

        with open(storage_path, "wb") as f:
            f.write(raw_bytes)

        report = Report(
            id=report_id,
            report_number=rep_num,
            report_type=report_kind,
            target_id=target_id,
            format=format_lower.upper(),
            file_path=storage_path,
            file_hash_sha256=sha256_hash,
            file_size_bytes=len(raw_bytes),
            generated_by=actor,
            created_at=now_iso,
        )
        db.add(report)

        AuditService.log(
            db=db,
            action="REPORT_GENERATED",
            entity_type="Report",
            entity_id=report_id,
            actor=actor,
            ip_address=ip_address,
            metadata={"format": format_lower, "report_number": rep_num, "target_id": target_id},
        )

        db.commit()
        db.refresh(report)
        return report

    @classmethod
    def get_report_file(cls, db: Session, report_id: str) -> tuple[str, str]:
        """Safely retrieve report file path and verify path traversal protection."""
        stmt = select(Report).where(Report.id == report_id)
        report = db.scalar(stmt)
        if not report or not report.file_path:
            raise FileNotFoundError(f"Report not found: {report_id}")

        safe_base_dir = os.path.abspath(settings.REPORTS_DIR)
        target_path = os.path.abspath(report.file_path)

        # Enforce that the target file is strictly inside the authorized reports directory
        if not target_path.startswith(safe_base_dir):
            raise PermissionError("Path traversal violation detected.")

        if not os.path.isfile(target_path):
            raise FileNotFoundError("Report file is missing from archive.")

        filename = os.path.basename(target_path)
        return target_path, filename
