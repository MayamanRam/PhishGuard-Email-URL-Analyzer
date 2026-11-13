"""Suspicious Attachment Metadata Forensics Engine.

Inspects attachment metadata, filenames, hashes, and MIME declarations
without executing payloads or invoking dangerous unpackers.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from app.attachment_analysis.yara_engine import LocalYaraScanner, YaraMatch


@dataclass
class AttachmentForensicResult:
    filename: str
    declared_content_type: str
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    primary_extension: str
    has_double_extension: bool
    second_extension: str | None
    is_executable_or_script: bool
    is_disk_image: bool
    is_macro_enabled: bool
    is_archive: bool
    has_mime_mismatch: bool
    has_space_padding_evasion: bool
    suspicious_naming_pattern: bool
    anomalies: list[str]
    yara_matches: list[YaraMatch] = field(default_factory=list)


class AttachmentForensicsAnalyzer:
    """Forensic inspector for email attachments."""

    EXECUTABLE_AND_SCRIPT_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".cpl", ".msi", ".jar",
    }

    DISK_IMAGE_EXTENSIONS = {
        ".iso", ".img", ".vhd", ".vhdx", ".dmg",
    }

    MACRO_EXTENSIONS = {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace",
    }

    SUSPICIOUS_NAME_PATTERNS = [
        r"remittance", r"payment.*(?:receipt|slip|advice)", r"wire.*transfer",
        r"invoice.*(?:urgent|overdue|due|\d+)", r"po(?:_|-|\s)?(?:order|\d+)",
        r"swift.*confirmation", r"dhl.*delivery", r"fedex.*tracking",
        r"e-?ticket", r"statement.*(?:oct|nov|dec|jan|feb|mar|apr|may|jun|jul|aug|sep)",
    ]

    def __init__(self) -> None:
        self.yara_scanner = LocalYaraScanner()

    def analyze(
        self,
        filename: str,
        declared_content_type: str,
        size_bytes: int,
        sha256_hash: str,
        md5_hash: str,
        raw_payload: bytes = b"",
    ) -> AttachmentForensicResult:
        """Inspect attachment attributes and identify evasion/phishing indicators."""
        clean_name = filename.strip()
        name_lower = clean_name.lower()

        # Check for space padding evasion (e.g., 'invoice.pdf    .exe')
        has_space_padding = bool(re.search(r"\.[a-zA-Z0-9]{2,4}\s+\.[a-zA-Z0-9]{2,4}", clean_name))

        # Extract extensions
        parts = clean_name.split(".")
        primary_ext = ("." + parts[-1].lower()) if len(parts) > 1 else ""
        has_double_ext = False
        second_ext: str | None = None

        if len(parts) > 2:
            has_double_ext = True
            second_ext = "." + parts[-2].lower()

        is_exec = primary_ext in self.EXECUTABLE_AND_SCRIPT_EXTENSIONS
        is_disk = primary_ext in self.DISK_IMAGE_EXTENSIONS
        is_macro = primary_ext in self.MACRO_EXTENSIONS
        is_arch = primary_ext in self.ARCHIVE_EXTENSIONS

        # MIME mismatch checks
        mime_lower = (declared_content_type or "").lower()
        has_mime_mismatch = False
        if is_exec and ("image/" in mime_lower or "pdf" in mime_lower or "text/" in mime_lower):
            has_mime_mismatch = True
        elif is_disk and "image/" in mime_lower:  # disk image claimed as photo
            has_mime_mismatch = True

        # Suspicious naming regex
        suspicious_naming = any(
            re.search(pat, name_lower) for pat in self.SUSPICIOUS_NAME_PATTERNS
        )

        anomalies: list[str] = []

        if is_exec:
            anomalies.append(f"Dangerous executable or script extension: '{primary_ext}'")
        if is_disk:
            anomalies.append(f"Disk image container extension: '{primary_ext}' (often used to bypass Mark-of-the-Web)")
        if is_macro:
            anomalies.append(f"Macro-enabled document extension: '{primary_ext}'")
        if has_double_ext:
            anomalies.append(f"Double extension detected: '{second_ext}{primary_ext}'")
        if has_space_padding:
            anomalies.append("Filename contains space padding to conceal the true extension")
        if has_mime_mismatch:
            anomalies.append(f"MIME type mismatch: declared '{declared_content_type}' but extension is '{primary_ext}'")
        if suspicious_naming and (is_exec or is_macro or is_arch or has_double_ext):
            anomalies.append("Generic financial/delivery pretext naming pattern combined with risky file type")

        # Run defensive in-memory YARA scan
        yara_matches: list[YaraMatch] = []
        if raw_payload:
            yara_matches = self.yara_scanner.scan_bytes(raw_payload, clean_name)
            for ym in yara_matches:
                anomalies.append(f"YARA Rule Matched [{ym.rule_name}]: {ym.description}")

        return AttachmentForensicResult(
            filename=clean_name,
            declared_content_type=declared_content_type,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            md5_hash=md5_hash,
            primary_extension=primary_ext,
            has_double_extension=has_double_ext,
            second_extension=second_ext,
            is_executable_or_script=is_exec,
            is_disk_image=is_disk,
            is_macro_enabled=is_macro,
            is_archive=is_arch,
            has_mime_mismatch=has_mime_mismatch,
            has_space_padding_evasion=has_space_padding,
            suspicious_naming_pattern=suspicious_naming,
            anomalies=anomalies,
            yara_matches=yara_matches,
        )

