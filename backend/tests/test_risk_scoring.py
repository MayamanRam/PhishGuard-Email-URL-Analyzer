"""Tests for Explainable Phishing Risk Scoring Engine."""

from app.detection.engine import TriggeredFinding
from app.scoring.calculator import PhishingRiskScorer


def test_risk_scorer_empty_findings_is_zero():
    scorer = PhishingRiskScorer()
    result = scorer.calculate([])

    assert result.final_score == 0.0
    assert result.severity_level == "low"
    assert result.is_corroborated_threat is False
    assert all(val == 0.0 for val in result.category_scores.values())


def test_single_heuristic_cannot_reach_critical_score():
    """Verify that a single rule (even with base weight 30 and critical severity) cannot yield Critical (>85)."""
    scorer = PhishingRiskScorer()
    single_rule = TriggeredFinding(
        rule_id="ATT-01",
        rule_name="Executable Attachment",
        category="ATTACH",
        severity="critical",
        base_weight=30.0,
        confidence_multiplier=0.95,
        effective_score=28.5,
        description="Dangerous executable",
        evidence_data={},
        remediation_advice="",
        mitre_attack_id="T1204.002",
    )

    result = scorer.calculate([single_rule])

    # Single category score is capped and diminishing returns apply
    assert result.final_score < 35.0
    assert result.severity_level in ("low", "moderate")
    assert result.severity_level != "critical"
    assert result.is_corroborated_threat is False


def test_legitimate_newsletter_false_positive_resistance():
    """Verify that a typical marketing email (missing SPF, slight header mismatch) remains Low."""
    scorer = PhishingRiskScorer()
    minor_findings = [
        TriggeredFinding(
            rule_id="HDR-02",
            rule_name="From vs Return-Path Mismatch",
            category="HEADER",
            severity="medium",
            base_weight=12.0,
            confidence_multiplier=0.70,
            effective_score=8.4,
            description="Newsletter sender relay mismatch",
            evidence_data={},
            remediation_advice="",
            mitre_attack_id=None,
        ),
        TriggeredFinding(
            rule_id="URL-08",
            rule_name="Long URL with Tracking Params",
            category="URL",
            severity="low",
            base_weight=8.0,
            confidence_multiplier=0.60,
            effective_score=4.8,
            description="Campaign tracking token",
            evidence_data={},
            remediation_advice="",
            mitre_attack_id=None,
        ),
    ]

    result = scorer.calculate(minor_findings)

    assert result.final_score < 25.0
    assert result.severity_level == "low"


def test_corroborated_multi_vector_threat_scores_critical():
    """Verify that multi-vector threats (auth fail + brand spoof + executable att + urgency) achieve Critical."""
    scorer = PhishingRiskScorer()
    multi_findings = [
        # AUTH
        TriggeredFinding("AUTH-04", "DMARC Fail", "AUTH", "critical", 30.0, 0.90, 27.0, "", {}, "", None),
        # SENDER
        TriggeredFinding("SND-01", "Display Name Spoof", "SENDER", "high", 25.0, 0.90, 22.5, "", {}, "", None),
        # URL
        TriggeredFinding("URL-01", "IP Host in Link", "URL", "high", 25.0, 0.90, 22.5, "", {}, "", None),
        TriggeredFinding("URL-03", "Brand Impersonation in Link", "URL", "high", 25.0, 0.90, 22.5, "", {}, "", None),
        # ATTACH
        TriggeredFinding("ATT-01", "Executable Attachment", "ATTACH", "critical", 30.0, 0.95, 28.5, "", {}, "", None),
        # CONTENT
        TriggeredFinding("CNT-01", "Urgency Pretext", "CONTENT", "medium", 12.0, 0.70, 8.4, "", {}, "", None),
    ]

    result = scorer.calculate(multi_findings)

    assert result.final_score >= 85.0
    assert result.final_score <= 100.0
    assert result.severity_level == "critical"
    assert result.is_corroborated_threat is True

