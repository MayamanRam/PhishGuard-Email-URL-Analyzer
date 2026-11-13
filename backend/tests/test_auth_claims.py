"""Tests for Email Authentication Header Claims Auditor."""

from app.email_analysis.auth_claims import EmailAuthenticationAuditor


def test_auth_claims_spf_fail_dkim_fail_dmarc_fail():
    auditor = EmailAuthenticationAuditor()
    auth_headers = [
        "mx.google.com; spf=fail (google.com: domain of spoof@victim.com does not designate 192.0.2.1 as permitted sender) smtp.mailfrom=spoof@victim.com; dkim=fail header.i=@victim.com; dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=victim.com",
    ]
    received_spf = [
        "fail (google.com: domain of spoof@victim.com does not designate 192.0.2.1 as permitted sender) client-ip=192.0.2.1;",
    ]

    report = auditor.audit(auth_headers, received_spf)

    assert report.spf.result == "fail"
    assert report.dkim.result == "fail"
    assert report.dmarc.result == "fail"
    assert report.is_unverified_header_claim is True
    assert "Authentication Failure Claimed" in report.summary_verdict
    assert len(report.warnings) >= 3
    assert "NOTE: Authentication claims reflect header claims" in report.disclaimer


def test_auth_claims_legitimate_pass():
    auditor = EmailAuthenticationAuditor()
    auth_headers = [
        "mx.google.com; spf=pass (google.com: domain of info@example.com designates 198.51.100.1 as permitted sender) smtp.mailfrom=info@example.com; dkim=pass header.i=@example.com header.s=s1; dmarc=pass header.from=example.com",
    ]

    report = auditor.audit(auth_headers)

    assert report.spf.result == "pass"
    assert report.dkim.result == "pass"
    assert report.dmarc.result == "pass"
    assert report.is_unverified_header_claim is True
    assert "Pass" in report.summary_verdict
    assert len(report.warnings) == 0


def test_auth_claims_missing():
    auditor = EmailAuthenticationAuditor()
    report = auditor.audit([])

    assert report.spf.result == "missing"
    assert report.dkim.result == "missing"
    assert report.dmarc.result == "missing"
    assert "Inconclusive" in report.summary_verdict

