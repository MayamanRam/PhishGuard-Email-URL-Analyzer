"""Test Suite for Database Models, Relationships, and Constraints."""

import pytest
from app.models.analysis_run import AnalysisRun
from app.models.email_artifact import EmailArtifact
from app.models.url_artifact import UrlArtifact
from app.models.attachment_artifact import AttachmentArtifact
from app.models.detection_rule import DetectionRule
from app.models.finding import Finding
from app.models.investigation_case import InvestigationCase
from app.models.case_artifact_association import CaseArtifactAssociation
from app.models.investigation_note import InvestigationNote
from app.models.report import Report
from app.models.audit_event import AuditEvent
from app.models.app_setting import AppSetting


def test_analysis_run_and_artifact_creation(test_db_session):
    """Asserts that AnalysisRun and attached artifacts persist with correct foreign keys."""
    run = AnalysisRun(
        artifact_type="EMAIL",
        risk_score=75,
        risk_level="HIGH",
        summary="High indicator phishing email with brand impersonation.",
        confidence_score=0.9,
        total_findings=2,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        execution_time_ms=124.5,
    )
    test_db_session.add(run)
    test_db_session.commit()
    test_db_session.refresh(run)

    assert run.id.startswith("run_")
    assert run.risk_score == 75

    # Add EmailArtifact
    eml = EmailArtifact(
        analysis_id=run.id,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        subject="Account Suspension Notice",
        from_header="Security Team <security@paypa1-support.com>",
        from_address="security@paypa1-support.com",
        from_domain="paypa1-support.com",
        from_display_name="Security Team",
        reply_to_address="attacker@harvest.com",
    )
    test_db_session.add(eml)

    # Add UrlArtifact
    url = UrlArtifact(
        analysis_id=run.id,
        original_url="http://192.168.1.10/login",
        normalized_url="http://192.168.1.10/login",
        scheme="http",
        hostname="192.168.1.10",
        registered_domain="192.168.1.10",
        public_suffix="",
        is_ip_host=1,
    )
    test_db_session.add(url)

    # Add AttachmentArtifact
    att = AttachmentArtifact(
        analysis_id=run.id,
        filename="Invoice_2026.pdf.exe",
        reported_mime_type="application/octet-stream",
        detected_extension=".exe",
        has_double_extension=1,
        is_executable_type=1,
        file_size_bytes=45056,
        sha256_hash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    test_db_session.add(att)

    test_db_session.commit()
    test_db_session.refresh(run)

    assert run.email_artifact is not None
    assert run.email_artifact.from_domain == "paypa1-support.com"
    assert len(run.url_artifacts) == 1
    assert run.url_artifacts[0].is_ip_host == 1
    assert len(run.attachment_artifacts) == 1
    assert run.attachment_artifacts[0].has_double_extension == 1


def test_investigation_case_workflow(test_db_session):
    """Asserts that InvestigationCase and notes function correctly."""
    case = InvestigationCase(
        case_number="PG-CASE-2026-0001",
        title="Suspicious Executive Impersonation",
        status="OPEN",
        severity="HIGH",
        classification="UNCLASSIFIED",
    )
    test_db_session.add(case)
    test_db_session.commit()
    test_db_session.refresh(case)

    assert case.id.startswith("case_")

    note = InvestigationNote(
        case_id=case.id,
        author="lead_analyst",
        note_text="Sender domain registered 2 days ago; credential harvesting form identified.",
    )
    test_db_session.add(note)
    test_db_session.commit()
    test_db_session.refresh(case)

    assert len(case.notes) == 1
    assert case.notes[0].author == "lead_analyst"


def test_audit_event_logging(test_db_session):
    """Asserts that AuditEvents are recorded with valid status and timestamps."""
    event = AuditEvent(
        event_type="EMAIL_SUBMITTED",
        object_type="ANALYSIS",
        object_id="run_12345",
        status="SUCCESS",
        details_json='{"filename": "phish.eml", "sha256": "abc123"}',
        client_ip="127.0.0.1",
    )
    test_db_session.add(event)
    test_db_session.commit()
    test_db_session.refresh(event)

    assert event.id.startswith("aud_")
    assert event.event_type == "EMAIL_SUBMITTED"

