"""Core Threat Analysis Orchestration Service.

Coordinates defensive parsing, static heuristic engines, detection rules,
risk scoring, database persistence, and evidence preservation.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.attachment_analysis.forensics import AttachmentForensicsAnalyzer
from app.core.config import settings
from app.detection.engine import DetectionEngine
from app.email_analysis.auth_claims import EmailAuthenticationAuditor
from app.email_analysis.headers import EmailHeaderAnalyzer
from app.email_analysis.parser import DefensiveEmailParser
from app.models import (
    AnalysisRun,
    AttachmentArtifact,
    EmailArtifact,
    Finding,
    UrlArtifact,
)
from app.scoring.calculator import PhishingRiskScorer
from app.services.audit_service import AuditService
from app.url_analysis.engine import StaticUrlAnalyzer


class AnalysisService:
    """Coordinates email and URL analysis pipelines."""

    def __init__(self) -> None:
        self.email_parser = DefensiveEmailParser()
        self.header_analyzer = EmailHeaderAnalyzer()
        self.auth_auditor = EmailAuthenticationAuditor()
        self.url_analyzer = StaticUrlAnalyzer()
        self.att_analyzer = AttachmentForensicsAnalyzer()
        self.detection_engine = DetectionEngine()
        self.risk_scorer = PhishingRiskScorer()

    def analyze_email(
        self,
        db: Session,
        raw_email_bytes: bytes,
        source_filename: str = "submitted_email.eml",
        actor: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> dict[str, Any]:
        """Execute full defensive analysis of an RFC 5322 email."""
        start_time = time.perf_counter()

        # 1. Parse email safely
        parsed = self.email_parser.parse(raw_email_bytes)

        # 2. Inspect headers & hops
        hops = self.header_analyzer.analyze_routing_hops(parsed.received_headers)
        sender_analysis = self.header_analyzer.analyze_sender_identities(
            from_header=parsed.from_header,
            reply_to_header=parsed.reply_to_header,
            return_path_header=parsed.return_path_header,
        )

        # 3. Audit authentication claims (with offline cryptographic DKIM verification)
        auth_report = self.auth_auditor.audit(
            auth_results_headers=parsed.auth_results_headers,
            received_spf_headers=parsed.all_headers.get("received-spf", []),
            all_headers=parsed.all_headers,
            raw_eml=raw_email_bytes,
            db=db,
        )

        # 4. Analyze extracted URLs
        url_results = [self.url_analyzer.analyze(link.href) for link in parsed.links]

        # 5. Inspect attachments
        att_results = [
            self.att_analyzer.analyze(
                filename=att.filename,
                declared_content_type=att.content_type,
                size_bytes=att.size_bytes,
                sha256_hash=att.sha256_hash,
                md5_hash=att.md5_hash,
                raw_payload=att.raw_payload,
            )
            for att in parsed.attachments
        ]

        # 6. Evaluate detection rules
        findings = self.detection_engine.evaluate_email(
            email_data=parsed,
            hops=hops,
            sender_analysis=sender_analysis,
            auth_report=auth_report,
            url_results=url_results,
            attachment_results=att_results,
        )

        # 7. Compute explainable risk score
        score_result = self.risk_scorer.calculate(findings)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # 8. Store raw evidence safely to vault
        evidence_filename = f"{parsed.sha256_fingerprint}.eml"
        evidence_path = os.path.join(str(settings.EVIDENCE_DIR), evidence_filename)
        os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
        if not os.path.exists(evidence_path):
            with open(evidence_path, "wb") as f:
                f.write(raw_email_bytes)

        # 9. Persist to Database
        now_iso = datetime.now(timezone.utc).isoformat()
        run_id = f"run_{uuid.uuid4().hex}"
        email_art_id = f"eml_{uuid.uuid4().hex}"

        summary_json = json.dumps({
            "target": parsed.subject or "No Subject",
            "formula_explanation": score_result.formula_explanation,
            "category_scores": score_result.category_scores,
            "is_corroborated_threat": score_result.is_corroborated_threat,
            "links_count": len(url_results),
            "attachments_count": len(att_results),
            "hops_count": len(hops),
            "auth_verdict": auth_report.summary_verdict,
        })

        run = AnalysisRun(
            id=run_id,
            artifact_type="EMAIL",
            risk_score=round(score_result.final_score),
            risk_level=score_result.severity_level.upper(),
            summary=summary_json,
            confidence_score=1.0,
            total_findings=len(score_result.triggered_rules),
            sha256_hash=parsed.sha256_fingerprint,
            execution_time_ms=round(elapsed_ms, 2),
            created_at=now_iso,
            is_immutable=1,
        )
        db.add(run)

        email_artifact = EmailArtifact(
            id=email_art_id,
            analysis_id=run_id,
            evidence_file_path=evidence_path,
            sha256_hash=parsed.sha256_fingerprint,
            message_id=parsed.message_id_header,
            subject=parsed.subject,
            from_header=parsed.from_header,
            from_address=sender_analysis.from_address,
            from_domain=sender_analysis.from_domain,
            from_display_name=sender_analysis.from_display_name,
            reply_to_address=sender_analysis.reply_to_address,
            return_path_address=sender_analysis.return_path_address,
            sender_address=sender_analysis.sender_address,
            date_header=parsed.date_header,
            auth_results_raw=json.dumps({
                "spf": auth_report.spf.__dict__,
                "dkim": auth_report.dkim.__dict__,
                "dmarc": auth_report.dmarc.__dict__,
                "verdict": auth_report.summary_verdict,
                "warnings": auth_report.warnings,
                "dkim_offline": auth_report.dkim_offline_verification,
            }, default=str),
            routing_hops_json=json.dumps([h.__dict__ for h in hops], default=str),
            body_plain_length=len(parsed.plain_text_body),
            body_html_length=len(parsed.html_body_raw),
            attachment_count=len(att_results),
            url_count=len(url_results),
            submitted_at=now_iso,
            is_immutable=1,
        )
        db.add(email_artifact)

        # Persist URL artifacts
        for u_res in url_results:
            u_art = UrlArtifact(
                id=f"url_{uuid.uuid4().hex}",
                analysis_id=run_id,
                original_url=u_res.original_url,
                normalized_url=u_res.normalized_url,
                scheme=u_res.scheme,
                hostname=u_res.hostname,
                registered_domain=u_res.registrable_domain,
                public_suffix=u_res.public_suffix,
                port=u_res.port,
                path=u_res.path,
                query_string=u_res.query,
                is_ip_host=1 if u_res.has_ip_hostname else 0,
                has_punycode=1 if u_res.is_punycode else 0,
                has_userinfo=1 if u_res.has_userinfo_spoof else 0,
                redirect_param_count=1 if u_res.has_open_redirect_param else 0,
                display_text=None,
                text_destination_mismatch=0,
                detected_brands_json=json.dumps([u_res.impersonated_brand_name] if u_res.impersonated_brand_name else []),
                submitted_at=now_iso,
                is_immutable=1,
            )
            db.add(u_art)

        # Persist Attachment artifacts
        for att_res in att_results:
            a_art = AttachmentArtifact(
                id=f"att_{uuid.uuid4().hex}",
                analysis_id=run_id,
                filename=att_res.filename,
                reported_mime_type=att_res.declared_content_type,
                detected_extension=att_res.primary_extension,
                has_double_extension=1 if att_res.has_double_extension else 0,
                is_executable_type=1 if att_res.is_executable_or_script else 0,
                is_archive_type=1 if att_res.is_archive else 0,
                file_size_bytes=att_res.size_bytes,
                sha256_hash=att_res.sha256_hash,
                submitted_at=now_iso,
                is_immutable=1,
            )
            db.add(a_art)

        # Persist Findings
        for finding in score_result.triggered_rules:
            f_db = Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                analysis_id=run_id,
                rule_id=finding.rule_id,
                title=finding.rule_name,
                category=finding.category,
                severity=finding.severity.upper(),
                confidence=finding.confidence_multiplier,
                evidence_details=json.dumps(finding.evidence_data, default=str),
                recommended_action=finding.remediation_advice,
                created_at=now_iso,
                is_immutable=1,
            )
            db.add(f_db)

        # Log audit trail
        AuditService.log(
            db=db,
            action="EMAIL_ANALYZED",
            entity_type="AnalysisRun",
            entity_id=run_id,
            actor=actor,
            ip_address=ip_address,
            metadata={
                "subject": parsed.subject,
                "risk_score": score_result.final_score,
                "severity": score_result.severity_level,
                "findings_count": len(score_result.triggered_rules),
            },
        )

        db.commit()
        db.refresh(run)

        return {
            "run_id": run.id,
            "target_type": "email",
            "subject": parsed.subject,
            "risk_score": score_result.final_score,
            "severity": score_result.severity_level,
            "formula_explanation": score_result.formula_explanation,
            "category_scores": score_result.category_scores,
            "category_details": [d.__dict__ for d in score_result.category_details],
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "category": f.category,
                    "severity": f.severity,
                    "effective_score": f.effective_score,
                    "evidence": f.evidence_data,
                    "remediation": f.remediation_advice,
                    "mitre_id": f.mitre_attack_id,
                }
                for f in score_result.triggered_rules
            ],
            "email_metadata": {
                "sha256": parsed.sha256_fingerprint,
                "from": parsed.from_header,
                "to": parsed.to_header,
                "date": parsed.date_header,
                "sender_analysis": sender_analysis.__dict__,
                "auth_report": {
                    "spf": auth_report.spf.__dict__,
                    "dkim": auth_report.dkim.__dict__,
                    "dmarc": auth_report.dmarc.__dict__,
                    "verdict": auth_report.summary_verdict,
                    "warnings": auth_report.warnings,
                    "disclaimer": auth_report.disclaimer,
                    "dkim_offline_verification": auth_report.dkim_offline_verification,
                },
                "routing_hops": [h.__dict__ for h in hops],
            },
            "extracted_urls": [u.__dict__ for u in url_results],
            "attachments": [a.__dict__ for a in att_results],
            "created_at": now_iso,
        }

    def analyze_url(
        self,
        db: Session,
        raw_url: str,
        actor: str = "analyst",
        ip_address: str = "127.0.0.1",
    ) -> dict[str, Any]:
        """Execute static threat analysis of a single URL."""
        start_time = time.perf_counter()
        url_res = self.url_analyzer.analyze(raw_url)
        findings = self.detection_engine.evaluate_standalone_url(url_res)
        score_result = self.risk_scorer.calculate(findings)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        now_iso = datetime.now(timezone.utc).isoformat()
        run_id = f"run_{uuid.uuid4().hex}"
        url_hash = hashlib.sha256(url_res.normalized_url.encode("utf-8")).hexdigest()

        summary_json = json.dumps({
            "target": url_res.normalized_url,
            "formula_explanation": score_result.formula_explanation,
            "category_scores": score_result.category_scores,
            "is_corroborated_threat": score_result.is_corroborated_threat,
            "hostname": url_res.hostname,
            "registrable_domain": url_res.registrable_domain,
        })

        run = AnalysisRun(
            id=run_id,
            artifact_type="URL",
            risk_score=round(score_result.final_score),
            risk_level=score_result.severity_level.upper(),
            summary=summary_json,
            confidence_score=1.0,
            total_findings=len(score_result.triggered_rules),
            sha256_hash=url_hash,
            execution_time_ms=round(elapsed_ms, 2),
            created_at=now_iso,
            is_immutable=1,
        )
        db.add(run)

        url_art = UrlArtifact(
            id=f"url_{uuid.uuid4().hex}",
            analysis_id=run_id,
            original_url=url_res.original_url,
            normalized_url=url_res.normalized_url,
            scheme=url_res.scheme,
            hostname=url_res.hostname,
            registered_domain=url_res.registrable_domain,
            public_suffix=url_res.public_suffix,
            port=url_res.port,
            path=url_res.path,
            query_string=url_res.query,
            is_ip_host=1 if url_res.has_ip_hostname else 0,
            has_punycode=1 if url_res.is_punycode else 0,
            has_userinfo=1 if url_res.has_userinfo_spoof else 0,
            redirect_param_count=1 if url_res.has_open_redirect_param else 0,
            display_text=None,
            text_destination_mismatch=0,
            detected_brands_json=json.dumps([url_res.impersonated_brand_name] if url_res.impersonated_brand_name else []),
            submitted_at=now_iso,
            is_immutable=1,
        )
        db.add(url_art)

        for finding in score_result.triggered_rules:
            f_db = Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                analysis_id=run_id,
                rule_id=finding.rule_id,
                title=finding.rule_name,
                category=finding.category,
                severity=finding.severity.upper(),
                confidence=finding.confidence_multiplier,
                evidence_details=json.dumps(finding.evidence_data, default=str),
                recommended_action=finding.remediation_advice,
                created_at=now_iso,
                is_immutable=1,
            )
            db.add(f_db)

        AuditService.log(
            db=db,
            action="URL_ANALYZED",
            entity_type="AnalysisRun",
            entity_id=run_id,
            actor=actor,
            ip_address=ip_address,
            metadata={
                "url": url_res.normalized_url,
                "risk_score": score_result.final_score,
                "severity": score_result.severity_level,
            },
        )

        db.commit()
        db.refresh(run)

        return {
            "run_id": run.id,
            "target_type": "url",
            "url": url_res.normalized_url,
            "risk_score": score_result.final_score,
            "severity": score_result.severity_level,
            "formula_explanation": score_result.formula_explanation,
            "category_scores": score_result.category_scores,
            "category_details": [d.__dict__ for d in score_result.category_details],
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "category": f.category,
                    "severity": f.severity,
                    "effective_score": f.effective_score,
                    "evidence": f.evidence_data,
                    "remediation": f.remediation_advice,
                    "mitre_id": f.mitre_attack_id,
                }
                for f in score_result.triggered_rules
            ],
            "url_analysis": url_res.__dict__,
            "created_at": now_iso,
        }
