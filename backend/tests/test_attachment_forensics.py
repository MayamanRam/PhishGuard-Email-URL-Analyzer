"""Tests for Suspicious Attachment Forensics Engine."""

from app.attachment_analysis.forensics import AttachmentForensicsAnalyzer


def test_attachment_dangerous_executable_and_double_extension():
    analyzer = AttachmentForensicsAnalyzer()
    res = analyzer.analyze(
        filename="urgent_invoice.pdf.exe",
        declared_content_type="application/octet-stream",
        size_bytes=1048576,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5_hash="d41d8cd98f00b204e9800998ecf8427e",
    )

    assert res.is_executable_or_script is True
    assert res.has_double_extension is True
    assert res.second_extension == ".pdf"
    assert res.primary_extension == ".exe"
    assert len(res.anomalies) >= 2


def test_attachment_disk_image_and_macro_enabled():
    analyzer = AttachmentForensicsAnalyzer()

    iso_res = analyzer.analyze(
        filename="remittance_payment.iso",
        declared_content_type="application/x-iso9660-image",
        size_bytes=2097152,
        sha256_hash="abc",
        md5_hash="def",
    )
    assert iso_res.is_disk_image is True
    assert iso_res.suspicious_naming_pattern is True

    docm_res = analyzer.analyze(
        filename="statement_nov2026.docm",
        declared_content_type="application/vnd.ms-word.document.macroEnabled.12",
        size_bytes=45000,
        sha256_hash="123",
        md5_hash="456",
    )
    assert docm_res.is_macro_enabled is True


def test_attachment_clean_pdf_report():
    analyzer = AttachmentForensicsAnalyzer()
    clean_res = analyzer.analyze(
        filename="annual_financial_report_2026.pdf",
        declared_content_type="application/pdf",
        size_bytes=250000,
        sha256_hash="safe_hash",
        md5_hash="safe_md5",
    )

    assert clean_res.is_executable_or_script is False
    assert clean_res.has_double_extension is False
    assert clean_res.is_disk_image is False
    assert clean_res.is_macro_enabled is False
    assert len(clean_res.anomalies) == 0

