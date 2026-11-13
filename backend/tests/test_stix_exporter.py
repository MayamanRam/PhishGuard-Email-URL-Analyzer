"""Unit and Integration Tests for OASIS STIX 2.1 Threat Intelligence Bundle Exporter."""

from __future__ import annotations

import json
import pytest
from sqlalchemy.orm import Session

from app.models import AnalysisRun, Finding
from app.reports.generator import ReportGeneratorService
from app.reports.stix_exporter import StixExporter


def test_stix_exporter_bundle_structure():
    findings = [
        {
            "rule_id": "URL-002",
            "rule_name": "Punycode Homoglyph Domain",
            "category": "URL",
            "severity": "critical",
            "base_weight": 35.0,
            "confidence_multiplier": 1.0,
            "effective_score": 35.0,
            "mitre_attack_id": "T1566.002",
            "remediation_advice": "Block access immediately.",
            "evidence_data": {
                "url": "https://xn--pple-43d.com/login",
                "punycode": "xn--pple-43d.com",
            },
        },
        {
            "rule_id": "ATT-06",
            "rule_name": "YARA Signature Match on Attachment",
            "category": "ATTACHMENT",
            "severity": "critical",
            "base_weight": 35.0,
            "confidence_multiplier": 1.0,
            "effective_score": 35.0,
            "mitre_attack_id": "T1027",
            "remediation_advice": "Quarantine file.",
            "evidence_data": {
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "yara_matches": ["SUSPICIOUS_EMBEDDED_PE"],
            },
        },
    ]

    stix_json_str = StixExporter.export_bundle(
        title="Test Threat Export",
        target_identifier="https://xn--pple-43d.com/login",
        risk_score=85.0,
        severity="critical",
        findings=findings,
        summary_text="High risk credential harvesting and embedded binary.",
    )

    bundle = json.loads(stix_json_str)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert "objects" in bundle

    objs = bundle["objects"]
    types = [o["type"] for o in objs]

    # Must contain identity
    assert "identity" in types
    identity_obj = next(o for o in objs if o["type"] == "identity")
    assert identity_obj["name"] == "PhishGuard Threat Analysis Platform"

    # Must contain attack-patterns for T1566.002 and T1027
    attack_patterns = [o for o in objs if o["type"] == "attack-pattern"]
    mitre_ids = [ap["external_references"][0]["external_id"] for ap in attack_patterns]
    assert "T1566.002" in mitre_ids
    assert "T1027" in mitre_ids

    # Must contain indicators
    indicators = [o for o in objs if o["type"] == "indicator"]
    assert len(indicators) >= 1

    # Must contain relationships linking indicators to attack patterns
    relationships = [o for o in objs if o["type"] == "relationship"]
    assert len(relationships) >= 1
    assert all(r["relationship_type"] == "indicates" for r in relationships)


def test_report_generator_stix_format(test_db_session: Session):
    run = AnalysisRun(
        id="run_stix_test_01",
        artifact_type="EMAIL",
        risk_score=80,
        risk_level="HIGH",
        summary=json.dumps({"target": "invoice@malicious.com"}),
        confidence_score=1.0,
        total_findings=1,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        execution_time_ms=12.5,
        created_at="2026-11-13T12:00:00Z",
        is_immutable=1,
    )
    test_db_session.add(run)

    finding = Finding(
        id="fnd_stix_01",
        analysis_id="run_stix_test_01",
        rule_id="AUTH-01",
        title="SPF Hard Fail",
        category="AUTH",
        severity="HIGH",
        confidence=0.85,
        evidence_details=json.dumps({"domain": "malicious.com"}),
        recommended_action="Reject message",
        created_at="2026-11-13T12:00:00Z",
        is_immutable=1,
    )
    test_db_session.add(finding)
    test_db_session.commit()

    report = ReportGeneratorService.generate_report(
        db=test_db_session,
        format_type="stix",
        analysis_run_id="run_stix_test_01",
    )

    assert report.format == "STIX"
    assert report.file_path.endswith(".stix.json")

    file_path, filename = ReportGeneratorService.get_report_file(test_db_session, report.id)
    with open(file_path, "r", encoding="utf-8") as f:
        content = json.load(f)

    assert content["type"] == "bundle"
    assert any(o["type"] == "attack-pattern" and o["external_references"][0]["external_id"] == "T1566.002" for o in content["objects"])

