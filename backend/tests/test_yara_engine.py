"""Unit and Integration Tests for Pure-Python Local YARA Signature Engine."""

from __future__ import annotations

import pytest

from app.attachment_analysis.forensics import AttachmentForensicsAnalyzer
from app.attachment_analysis.yara_engine import LocalYaraScanner, YaraRule
from app.detection.engine import DetectionEngine
from app.email_analysis.parser import ParsedEmail, ExtractedAttachment
from app.email_analysis.headers import SenderIdentityAnalysis
from app.email_analysis.auth_claims import AuthenticationAuditReport, SPFClaim, DKIMClaim, DMARCClaim


def test_yara_clean_payload():
    scanner = LocalYaraScanner()
    clean_bytes = b"Hello, this is a completely harmless text document for accounting."
    matches = scanner.scan_bytes(clean_bytes, filename="memo.txt")
    assert len(matches) == 0


def test_yara_embedded_pe_detection():
    scanner = LocalYaraScanner()
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode.PE\x00\x00"
    matches = scanner.scan_bytes(pe_bytes, filename="invoice.pdf")
    assert any(m.rule_name == "SUSPICIOUS_EMBEDDED_PE" for m in matches)
    pe_match = next(m for m in matches if m.rule_name == "SUSPICIOUS_EMBEDDED_PE")
    assert pe_match.severity == "CRITICAL"
    assert "T1036.008" in str(pe_match.mitre_attack_id)


def test_yara_obfuscated_powershell_cradle():
    scanner = LocalYaraScanner()
    payload = b"powershell.exe -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    matches = scanner.scan_bytes(payload)
    assert any(m.rule_name == "OBFUSCATED_POWERSHELL_CRADLE" for m in matches)


def test_yara_vba_macro_execution_chain():
    scanner = LocalYaraScanner()
    payload = b"Sub Auto_Open()\n Dim wsh: Set wsh = CreateObject(\"WScript.Shell\")\n wsh.Run \"calc\"\nEnd Sub"
    matches = scanner.scan_bytes(payload, filename="document.docm")
    assert any(m.rule_name == "VBA_MACRO_EXECUTION_CHAIN" for m in matches)
    vba_match = next(m for m in matches if m.rule_name == "VBA_MACRO_EXECUTION_CHAIN")
    assert vba_match.severity == "CRITICAL"


def test_yara_html_smuggling_payload():
    scanner = LocalYaraScanner()
    payload = (
        b"<script>"
        b"var blob = new Blob([data], {type: 'application/octet-stream'}); "
        b"var url = URL.createObjectURL(blob); "
        b"window.navigator.msSaveOrOpenBlob(blob, 'run.exe');"
        b"</script>"
    )
    matches = scanner.scan_bytes(payload, filename="statement.html")
    assert any(m.rule_name == "HTML_SMUGGLING_PAYLOAD" for m in matches)


def test_yara_script_downloader_objects():
    scanner = LocalYaraScanner()
    payload = b"var x = new ActiveXObject('MSXML2.XMLHTTP'); var s = new ActiveXObject('ADODB.Stream');"
    matches = scanner.scan_bytes(payload, filename="loader.js")
    assert any(m.rule_name == "SCRIPT_DOWNLOADER_OBJECTS" for m in matches)


def test_attachment_forensics_integration_with_yara():
    analyzer = AttachmentForensicsAnalyzer()
    malicious_bytes = b"MZ\x00\x00This program cannot be run in DOS mode.PE\x00\x00"

    result = analyzer.analyze(
        filename="bonus.pdf",
        declared_content_type="application/pdf",
        size_bytes=len(malicious_bytes),
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5_hash="d41d8cd98f00b204e9800998ecf8427e",
        raw_payload=malicious_bytes,
    )

    assert len(result.yara_matches) >= 1
    assert any(m.rule_name == "SUSPICIOUS_EMBEDDED_PE" for m in result.yara_matches)
    assert any("YARA" in a for a in result.anomalies)


def test_detection_engine_triggers_att06_on_yara_match():
    engine = DetectionEngine()
    analyzer = AttachmentForensicsAnalyzer()
    malicious_bytes = b"Sub AutoOpen()\nCreateObject('WScript.Shell').Run 'calc'\nEnd Sub"

    att_result = analyzer.analyze(
        filename="invoice.docm",
        declared_content_type="application/vnd.ms-word.document.macroEnabled.12",
        size_bytes=len(malicious_bytes),
        sha256_hash="1122334455",
        md5_hash="66778899",
        raw_payload=malicious_bytes,
    )

    email_data = ParsedEmail(
        sha256_fingerprint="abc123def456",
        md5_fingerprint="11223344",
        raw_size_bytes=512,
        subject="Invoice doc",
        from_header="accounting@corp.com",
        to_header="user@company.com",
        cc_header="",
        reply_to_header="",
        return_path_header="",
        date_header="Mon, 1 Jan 2026 00:00:00 GMT",
        message_id_header="<123@corp.com>",
        all_headers={},
        received_headers=[],
        auth_results_headers=[],
        plain_text_body="",
        html_body_raw="",
        html_text_extracted="",
        links=[],
        form_actions=[],
        image_sources=[],
        attachments=[],
    )

    sender_analysis = SenderIdentityAnalysis(
        from_display_name="Accounting",
        from_address="accounting@corp.com",
        from_domain="corp.com",
        reply_to_address=None,
        reply_to_domain=None,
        return_path_address=None,
        return_path_domain=None,
        sender_address=None,
        sender_domain=None,
        has_from_reply_to_mismatch=False,
        has_from_return_path_mismatch=False,
        has_display_name_email_spoofing=False,
        has_brand_impersonation_in_name=False,
        detected_impersonated_brand=None,
        anomalies=[],
    )

    auth_report = AuthenticationAuditReport(
        spf=SPFClaim("pass", "corp.com", "1.2.3.4", "pass"),
        dkim=DKIMClaim("pass", "corp.com", "s1", "pass"),
        dmarc=DMARCClaim("pass", "corp.com", "none", "pass"),
        is_unverified_header_claim=False,
        summary_verdict="Pass",
        warnings=[],
        disclaimer="",
    )

    findings = engine.evaluate_email(
        email_data=email_data,
        hops=[],
        sender_analysis=sender_analysis,
        auth_report=auth_report,
        url_results=[],
        attachment_results=[att_result],
    )

    assert any(f.rule_id == "ATT-06" for f in findings)
    att06 = next(f for f in findings if f.rule_id == "ATT-06")
    assert att06.severity.upper() in ("HIGH", "CRITICAL")
