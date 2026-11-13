"""CSV Report Exporter with Formula Injection Protection.

Implements strict sanitization against CSV Formula Injection (CWE-1236)
by escaping leading characters (=, +, -, @, tab, CR) with single quotes.
"""

from __future__ import annotations

import csv
import io
from typing import Any


class CsvReportExporter:
    """Safe CSV exporter immune to spreadsheet formula execution."""

    DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

    @classmethod
    def sanitize_field(cls, value: Any) -> str:
        """Neutralize potential CSV formula injection payloads."""
        if value is None:
            return ""
        val_str = str(value)
        if val_str.startswith(cls.DANGEROUS_PREFIXES):
            return f"'{val_str}"
        return val_str

    @classmethod
    def export_findings(cls, findings_data: list[dict[str, Any]]) -> str:
        """Export findings to a safe CSV string."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        # Header
        writer.writerow([
            "Rule ID",
            "Rule Name",
            "Category",
            "Severity",
            "Base Weight",
            "Confidence",
            "Effective Score",
            "MITRE ATT&CK",
            "Remediation Advice",
        ])

        for f in findings_data:
            writer.writerow([
                cls.sanitize_field(f.get("rule_id")),
                cls.sanitize_field(f.get("rule_name")),
                cls.sanitize_field(f.get("category")),
                cls.sanitize_field(f.get("severity")),
                cls.sanitize_field(f.get("base_weight")),
                cls.sanitize_field(f.get("confidence_multiplier")),
                cls.sanitize_field(f.get("effective_score")),
                cls.sanitize_field(f.get("mitre_attack_id")),
                cls.sanitize_field(f.get("remediation_advice")),
            ])

        return output.getvalue()

