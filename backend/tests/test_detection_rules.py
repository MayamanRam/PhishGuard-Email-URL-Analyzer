"""Tests for Deterministic Detection Rules Engine."""

from app.attachment_analysis.forensics import AttachmentForensicResult
from app.detection.engine import DetectionEngine
from app.email_analysis.auth_claims import AuthenticationAuditReport, DKIMClaim, DMARCClaim, SPFClaim
from app.email_analysis.headers import RoutingHop, SenderIdentityAnalysis
from app.email_analysis.parser import ExtractedLink, ParsedEmail
from app.url_analysis.engine import StaticUrlAnalysisResult


def test_detection_engine_synthetic_phishing_email():
    engine = DetectionEngine()

    parsed_email = ParsedEmail(
        sha256_fingerprint="abc",
        md5_fingerprint="123",
        raw_size_bytes=1000,
        subject="URGENT: Your PayPal Account Has Been Suspended",
        from_header='"PayPal Security Team" <spoof@attacker-domain.ru>',
        to_header="victim@target.com",
        cc_header="",
        reply_to_header="phish-collector@scam.com",
        return_path_header="bounce@attacker-domain.ru",
        date_header="Thu, 12 Nov 2026 12:00:00 +0000",
        message_id_header="<123@attacker-domain.ru>",
        all_headers={},
        received_headers=[],
        auth_results_headers=[],
        plain_text_body="Your account is restricted. Immediate wire transfer or verification required within 24 hours.",
        html_body_raw="",
        html_text_extracted="Your account is restricted. Immediate wire transfer required.",
        links=[
            ExtractedLink(
                href="http://192.168.1.50/paypal-login",
                anchor_text="https://www.paypal.com/signin",
                is_mismatch=True,
            )
        ],
        form_actions=["http://192.168.1.50/harvest"],
        image_sources=[],
        attachments=[],
    )

    hops = [
        RoutingHop(
            hop_number=1,
            raw_header="from mail.attacker.ru",
            from_host="mail.attacker.ru",
            by_host="mx.victim.com",
            with_protocol="ESMTP",
            ip_address="198.51.100.5",
            is_private_ip=False,
            timestamp_raw="12 Nov 2026",
            timestamp_utc=None,
            delay_seconds=0.0,
            anomalies=[],
        )
    ]

    sender_analysis = SenderIdentityAnalysis(
        from_display_name="PayPal Security Team",
        from_address="spoof@attacker-domain.ru",
        from_domain="attacker-domain.ru",
        reply_to_address="phish-collector@scam.com",
        reply_to_domain="scam.com",
        return_path_address="bounce@attacker-domain.ru",
        return_path_domain="attacker-domain.ru",
        sender_address=None,
        sender_domain=None,
        has_from_reply_to_mismatch=True,
        has_from_return_path_mismatch=False,
        has_display_name_email_spoofing=False,
        has_brand_impersonation_in_name=True,
        detected_impersonated_brand="paypal",
        anomalies=["Brand impersonation"],
    )

    auth_report = AuthenticationAuditReport(
        spf=SPFClaim("fail", "attacker-domain.ru", "198.51.100.5", "spf=fail"),
        dkim=DKIMClaim("fail", "attacker-domain.ru", "s1", "dkim=fail"),
        dmarc=DMARCClaim("fail", "attacker-domain.ru", "reject", "dmarc=fail"),
        is_unverified_header_claim=True,
        summary_verdict="Authentication Failure Claimed",
        warnings=["SPF fail", "DKIM fail", "DMARC fail"],
        disclaimer="Unverified header claim",
    )

    url_result = StaticUrlAnalysisResult(
        original_url="http://192.168.1.50/paypal-login",
        normalized_url="http://192.168.1.50/paypal-login",
        scheme="http",
        hostname="192.168.1.50",
        port=None,
        path="/paypal-login",
        query="",
        fragment="",
        subdomain="",
        registrable_domain="192.168.1.50",
        public_suffix="",
        has_ip_hostname=True,
        ip_type="ipv4",
        has_userinfo_spoof=False,
        userinfo=None,
        is_punycode=False,
        decoded_punycode_host=None,
        has_mixed_script_homoglyphs=False,
        homoglyph_details=[],
        has_suspicious_tld=False,
        suspicious_tld_name=None,
        has_open_redirect_param=False,
        open_redirect_target=None,
        has_brand_impersonation=True,
        impersonated_brand_name="paypal",
        entropy=2.5,
        total_length=30,
        anomalies=["IP hostname"],
    )

    att_result = AttachmentForensicResult(
        filename="Security_Notice.pdf.exe",
        declared_content_type="application/octet-stream",
        size_bytes=50000,
        sha256_hash="hash123",
        md5_hash="md5123",
        primary_extension=".exe",
        has_double_extension=True,
        second_extension=".pdf",
        is_executable_or_script=True,
        is_disk_image=False,
        is_macro_enabled=False,
        is_archive=False,
        has_mime_mismatch=False,
        has_space_padding_evasion=False,
        suspicious_naming_pattern=False,
        anomalies=["Executable", "Double extension"],
    )

    findings = engine.evaluate_email(
        email_data=parsed_email,
        hops=hops,
        sender_analysis=sender_analysis,
        auth_report=auth_report,
        url_results=[url_result],
        attachment_results=[att_result],
    )

    triggered_ids = {f.rule_id for f in findings}
    assert "AUTH-01" in triggered_ids  # SPF fail
    assert "AUTH-03" in triggered_ids  # DKIM fail
    assert "AUTH-04" in triggered_ids  # DMARC fail
    assert "HDR-01" in triggered_ids   # From vs Reply-To mismatch
    assert "SND-02" in triggered_ids   # Brand impersonation in sender
    assert "URL-01" in triggered_ids   # Literal IP host
    assert "URL-07" in triggered_ids   # Anchor vs destination mismatch
    assert "ATT-01" in triggered_ids   # Executable attachment
    assert "ATT-02" in triggered_ids   # Double extension
    assert "CNT-01" in triggered_ids   # Urgency language
    assert "CNT-02" in triggered_ids   # HTML credential form action

