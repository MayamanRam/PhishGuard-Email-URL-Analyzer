"""Tests for Defensive RFC 5322 and MIME Email Parser."""

from app.email_analysis.parser import DefensiveEmailParser


def test_defensive_parser_plain_text():
    raw_email = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Monthly Security Digest\r\n"
        "Date: Thu, 12 Nov 2026 10:00:00 +0000\r\n"
        "Message-ID: <msg001@example.com>\r\n"
        "\r\n"
        "Please visit https://example.com/digest for details.\r\n"
    )

    parser = DefensiveEmailParser()
    result = parser.parse(raw_email)

    assert result.subject == "Monthly Security Digest"
    assert result.from_header == "sender@example.com"
    assert result.to_header == "recipient@example.com"
    assert "https://example.com/digest" in [l.href for l in result.links]
    assert len(result.sha256_fingerprint) == 64
    assert len(result.attachments) == 0


def test_defensive_parser_html_with_malicious_script_and_mismatched_link():
    raw_email = (
        "From: service@paypal-notice.com\r\n"
        "To: victim@target.com\r\n"
        "Subject: Urgent Account Suspension Notice\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body>"
        "<script>alert('malicious_payload');</script>"
        "<p>Your account is restricted. <a href=\"http://evil-phish.ru/login\">https://www.paypal.com/signin</a></p>"
        "<form action=\"http://harvest-credentials.com/submit\"><input name=\"pwd\"/></form>"
        "</body></html>"
    )

    parser = DefensiveEmailParser()
    result = parser.parse(raw_email)

    # Verify script was completely stripped
    assert "alert" not in result.html_text_extracted
    # Verify link and mismatch detection
    assert len(result.links) >= 1
    mismatch_link = next(l for l in result.links if "evil-phish.ru" in l.href)
    assert mismatch_link.is_mismatch is True
    assert "paypal.com" in mismatch_link.anchor_text
    # Verify form action extraction
    assert "http://harvest-credentials.com/submit" in result.form_actions


def test_defensive_parser_attachment_extraction():
    raw_email = (
        "From: billing@vendor.com\r\n"
        "To: accounts@company.com\r\n"
        "Subject: Overdue Invoice\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
        "\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "See attached invoice.\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "TVpQAAIAAAAAACC=\r\n"
        "--BOUNDARY--\r\n"
    )

    parser = DefensiveEmailParser()
    result = parser.parse(raw_email)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert att.size_bytes > 0
    assert len(att.sha256_hash) == 64

