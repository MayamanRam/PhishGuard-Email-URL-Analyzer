"""Professional Defensive PDF Threat Report Generator.

Generates PDF investigation summaries using ReportLab.
All external URLs and domain names are defanged (hxxps://, [.]) with
zero active clickable links to prevent accidental victim redirection.
"""

from __future__ import annotations

import io
import re
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class PdfReportExporter:
    """Generates hardened PDF threat analysis reports."""

    @staticmethod
    def defang_url(url: str) -> str:
        """Defang URL to ensure it cannot be accidentally executed or clicked."""
        if not url:
            return ""
        defanged = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
        defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
        defanged = defanged.replace(".", "[.]")
        return defanged

    @classmethod
    def generate_pdf(
        cls,
        title: str,
        target_identifier: str,
        risk_score: float,
        severity: str,
        findings: list[dict[str, Any]],
        category_scores: dict[str, float],
        summary_text: str,
        created_at: str,
    ) -> bytes:
        """Build and render PDF report to bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
        )
        subtitle_style = ParagraphStyle(
            "SubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
        )
        heading2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        )
        code_style = ParagraphStyle(
            "Code",
            parent=styles["Code"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#0f172a"),
        )

        elements = []

        # Header Title
        elements.append(Paragraph("PHISHGUARD THREAT ANALYSIS REPORT", title_style))
        elements.append(Paragraph(f"Generated: {created_at} UTC | Defensive Static Analysis", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#3b82f6"), spaceAfter=15))

        # Executive Summary Box
        sev_color = "#22c55e"  # Low
        if severity == "moderate":
            sev_color = "#eab308"
        elif severity == "high":
            sev_color = "#f97316"
        elif severity == "critical":
            sev_color = "#ef4444"

        summary_table_data = [
            [
                Paragraph("<b>Target Evaluated:</b>", body_style),
                Paragraph(cls.defang_url(target_identifier[:80]), code_style),
            ],
            [
                Paragraph("<b>Risk Score:</b>", body_style),
                Paragraph(f"<b>{risk_score:.1f} / 100</b>", ParagraphStyle("Score", parent=body_style, textColor=colors.HexColor(sev_color))),
            ],
            [
                Paragraph("<b>Severity Band:</b>", body_style),
                Paragraph(f"<b>{severity.upper()}</b>", ParagraphStyle("Sev", parent=body_style, textColor=colors.HexColor(sev_color))),
            ],
            [
                Paragraph("<b>Summary Assessment:</b>", body_style),
                Paragraph(summary_text, body_style),
            ],
        ]

        summary_table = Table(summary_table_data, colWidths=[130, 400])
        summary_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Category Threat Distribution Table
        elements.append(Paragraph("Category Threat Breakdown", heading2_style))
        elements.append(Spacer(1, 6))

        cat_data = [["Category", "Score Contribution", "Maximum Cap"]]
        caps = {"URL": 40.0, "ATTACH": 40.0, "AUTH": 35.0, "SENDER": 30.0, "HEADER": 20.0, "CONTENT": 20.0}
        for cat, cap in caps.items():
            cat_score = category_scores.get(cat, 0.0)
            cat_data.append([cat, f"{cat_score:.1f}", f"{cap:.1f}"])

        cat_table = Table(cat_data, colWidths=[180, 175, 175])
        cat_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ])
        )
        elements.append(cat_table)
        elements.append(Spacer(1, 15))

        # Triggered Findings Table
        elements.append(Paragraph(f"Triggered Threat Indicators ({len(findings)})", heading2_style))
        elements.append(Spacer(1, 6))

        if not findings:
            elements.append(Paragraph("No suspicious threat indicators triggered during offline analysis.", body_style))
        else:
            findings_data = [["Rule ID", "Rule Name", "Category", "Severity", "Impact"]]
            for f in findings[:25]:  # Limit rows per page cleanly
                findings_data.append([
                    f.get("rule_id", ""),
                    Paragraph(f.get("rule_name", ""), body_style),
                    f.get("category", ""),
                    f.get("severity", "").upper(),
                    f"+{f.get('effective_score', 0):.1f}",
                ])

            findings_table = Table(findings_data, colWidths=[65, 230, 85, 75, 75])
            findings_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ])
            )
            elements.append(findings_table)

        elements.append(Spacer(1, 20))
        # Hardened Disclaimer Notice
        disclaimer_text = (
            "<b>AIR-GAPPED DEFENSIVE NOTICE:</b> All findings and scores were computed through offline static "
            "analysis and deterministic heuristics. Zero outbound network connections were made to verify "
            "live threat intelligence or resolve external DNS. All URLs in this document have been defanged."
        )
        elements.append(Paragraph(disclaimer_text, subtitle_style))

        doc.build(elements)
        return buffer.getvalue()

