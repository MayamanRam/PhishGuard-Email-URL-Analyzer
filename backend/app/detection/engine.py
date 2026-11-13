"""Deterministic Detection Rule Evaluation Engine.

Executes detection rules across parsed email structures, routing hops,
authentication claims, static URL findings, and attachment forensics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.attachment_analysis.forensics import AttachmentForensicResult
from app.detection.catalog import RULE_CATALOG, RuleDefinition
from app.email_analysis.auth_claims import AuthenticationAuditReport
from app.email_analysis.headers import RoutingHop, SenderIdentityAnalysis
from app.email_analysis.parser import ParsedEmail
from app.url_analysis.engine import StaticUrlAnalysisResult


@dataclass
class TriggeredFinding:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    base_weight: float
    confidence_multiplier: float
    effective_score: float
    description: str
    evidence_data: dict[str, Any]
    remediation_advice: str
    mitre_attack_id: str | None


class DetectionEngine:
    """Evaluates deterministic rules and generates findings."""

    URGENCY_PATTERNS = [
        r"\b(?:urgent|immediately|within 24 hours|account (?:suspended|locked|terminated))\b",
        r"\b(?:unauthorized (?:access|activity)|verify your (?:identity|account|credentials))\b",
        r"\b(?:wire transfer|wire payment|gift cards?|bitcoin|crypto payment)\b",
        r"\b(?:final notice|action required|immediate action)\b",
    ]

    def evaluate_email(
        self,
        email_data: ParsedEmail,
        hops: list[RoutingHop],
        sender_analysis: SenderIdentityAnalysis,
        auth_report: AuthenticationAuditReport,
        url_results: list[StaticUrlAnalysisResult],
        attachment_results: list[AttachmentForensicResult],
    ) -> list[TriggeredFinding]:
        """Evaluate full email forensic data against the detection catalog."""
        findings: list[TriggeredFinding] = []

        # -------------------------------------------------------------
        # 1. AUTHENTICATION CLAIMS EVALUATION
        # -------------------------------------------------------------
        if auth_report.spf.result == "fail":
            findings.append(self._make_finding("AUTH-01", {
                "claim": auth_report.spf.raw_claim,
                "sender_domain": auth_report.spf.sender_domain,
            }))
        elif auth_report.spf.result == "softfail":
            findings.append(self._make_finding("AUTH-02", {
                "claim": auth_report.spf.raw_claim,
                "sender_domain": auth_report.spf.sender_domain,
            }))

        if auth_report.dkim.result == "fail":
            dkim_ev: dict[str, Any] = {
                "claim": auth_report.dkim.raw_claim,
                "signing_domain": auth_report.dkim.signing_domain,
            }
            if auth_report.dkim_offline_verification:
                dkim_ev["offline_verification"] = auth_report.dkim_offline_verification
            findings.append(self._make_finding("AUTH-03", dkim_ev))

        if auth_report.dmarc.result == "fail":
            findings.append(self._make_finding("AUTH-04", {
                "claim": auth_report.dmarc.raw_claim,
                "domain": auth_report.dmarc.header_from_domain,
                "action": auth_report.dmarc.action_taken,
            }))

        if (
            auth_report.spf.result == "missing"
            and auth_report.dkim.result == "missing"
            and auth_report.dmarc.result == "missing"
        ):
            findings.append(self._make_finding("AUTH-05", {
                "note": "No SPF, DKIM, or DMARC header records were observed."
            }))

        # -------------------------------------------------------------
        # 2. HEADER & ROUTING EVALUATION
        # -------------------------------------------------------------
        if sender_analysis.has_from_reply_to_mismatch:
            findings.append(self._make_finding("HDR-01", {
                "from_domain": sender_analysis.from_domain,
                "reply_to_domain": sender_analysis.reply_to_domain,
            }))

        if sender_analysis.has_from_return_path_mismatch:
            findings.append(self._make_finding("HDR-02", {
                "from_domain": sender_analysis.from_domain,
                "return_path_domain": sender_analysis.return_path_domain,
            }))

        # Check for timestamp inversion in hops
        inversion_hops = [h for h in hops if any("Clock skew" in a for a in h.anomalies)]
        if inversion_hops:
            findings.append(self._make_finding("HDR-03", {
                "affected_hops": [h.hop_number for h in inversion_hops],
                "anomalies": [h.anomalies for h in inversion_hops],
            }))

        if len(hops) == 1 and not hops[0].ip_address:
            findings.append(self._make_finding("HDR-04", {
                "hop_count": len(hops),
                "details": "Single hop without identifiable source IP.",
            }))

        # -------------------------------------------------------------
        # 3. SENDER IMPERSONATION EVALUATION
        # -------------------------------------------------------------
        if sender_analysis.has_display_name_email_spoofing:
            findings.append(self._make_finding("SND-01", {
                "display_name": sender_analysis.from_display_name,
                "actual_from_address": sender_analysis.from_address,
            }))

        if sender_analysis.has_brand_impersonation_in_name:
            findings.append(self._make_finding("SND-02", {
                "display_name": sender_analysis.from_display_name,
                "brand": sender_analysis.detected_impersonated_brand,
                "actual_from_domain": sender_analysis.from_domain,
            }))

        # Check for executive authority keywords
        disp_lower = sender_analysis.from_display_name.lower()
        if any(kw in disp_lower for kw in ["ceo", "cfo", "payroll", "human resources", "it support", "admin"]):
            if not sender_analysis.has_brand_impersonation_in_name:
                findings.append(self._make_finding("SND-03", {
                    "display_name": sender_analysis.from_display_name,
                    "from_domain": sender_analysis.from_domain,
                }))

        # -------------------------------------------------------------
        # 4. URL FINDINGS (Aggregated across all extracted links)
        # -------------------------------------------------------------
        self._evaluate_urls(url_results, findings)

        # Also check anchor text vs destination mismatch from parsed email
        mismatched_links = [l for l in email_data.links if l.is_mismatch]
        if mismatched_links:
            findings.append(self._make_finding("URL-07", {
                "mismatches": [
                    {"anchor": l.anchor_text, "destination": l.href} for l in mismatched_links[:5]
                ],
                "total_mismatches": len(mismatched_links),
            }))

        # -------------------------------------------------------------
        # 5. ATTACHMENT FINDINGS
        # -------------------------------------------------------------
        for att in attachment_results:
            if att.is_executable_or_script:
                findings.append(self._make_finding("ATT-01", {
                    "filename": att.filename,
                    "extension": att.primary_extension,
                    "sha256": att.sha256_hash,
                }))
            if att.has_double_extension:
                findings.append(self._make_finding("ATT-02", {
                    "filename": att.filename,
                    "double_extension": f"{att.second_extension}{att.primary_extension}",
                }))
            if att.is_disk_image:
                findings.append(self._make_finding("ATT-03", {
                    "filename": att.filename,
                    "extension": att.primary_extension,
                }))
            if att.is_macro_enabled:
                findings.append(self._make_finding("ATT-04", {
                    "filename": att.filename,
                    "extension": att.primary_extension,
                }))
            if att.has_mime_mismatch:
                findings.append(self._make_finding("ATT-05", {
                    "filename": att.filename,
                    "declared_mime": att.declared_content_type,
                    "extension": att.primary_extension,
                }))
            if att.yara_matches:
                for ym in att.yara_matches:
                    findings.append(self._make_finding("ATT-06", {
                        "filename": att.filename,
                        "rule_name": ym.rule_name,
                        "description": ym.description,
                        "matched_strings": ym.matched_strings,
                        "tags": ym.tags,
                    }))

        # -------------------------------------------------------------
        # 6. CONTENT HEURISTICS
        # -------------------------------------------------------------
        combined_body = (email_data.plain_text_body + " " + email_data.html_text_extracted).lower()
        matched_urgency: list[str] = []
        for pat in self.URGENCY_PATTERNS:
            matches = re.findall(pat, combined_body, re.IGNORECASE)
            if matches:
                matched_urgency.extend(matches[:2])

        if matched_urgency:
            findings.append(self._make_finding("CNT-01", {
                "matched_phrases": list(set(matched_urgency)),
                "subject": email_data.subject,
            }))

        if email_data.form_actions:
            findings.append(self._make_finding("CNT-02", {
                "form_actions": email_data.form_actions[:3],
                "total_forms": len(email_data.form_actions),
            }))

        return findings

    def evaluate_standalone_url(self, url_result: StaticUrlAnalysisResult) -> list[TriggeredFinding]:
        """Evaluate a standalone URL against the URL detection rules."""
        findings: list[TriggeredFinding] = []
        self._evaluate_urls([url_result], findings)
        return findings

    def _evaluate_urls(
        self,
        url_results: list[StaticUrlAnalysisResult],
        findings: list[TriggeredFinding],
    ) -> None:
        """Evaluate static URL results and append findings."""
        has_ip_urls = [u for u in url_results if u.has_ip_hostname]
        if has_ip_urls:
            findings.append(self._make_finding("URL-01", {
                "sample_urls": [u.normalized_url for u in has_ip_urls[:3]],
                "ip_types": list({u.ip_type for u in has_ip_urls if u.ip_type}),
            }))

        homoglyph_urls = [u for u in url_results if u.is_punycode or u.has_mixed_script_homoglyphs]
        if homoglyph_urls:
            findings.append(self._make_finding("URL-02", {
                "sample_urls": [u.normalized_url for u in homoglyph_urls[:3]],
                "decoded_hosts": [u.decoded_punycode_host for u in homoglyph_urls if u.decoded_punycode_host],
            }))

        brand_urls = [u for u in url_results if u.has_brand_impersonation]
        if brand_urls:
            findings.append(self._make_finding("URL-03", {
                "sample_urls": [u.normalized_url for u in brand_urls[:3]],
                "brands": list({u.impersonated_brand_name for u in brand_urls if u.impersonated_brand_name}),
            }))

        redirect_urls = [u for u in url_results if u.has_open_redirect_param]
        if redirect_urls:
            findings.append(self._make_finding("URL-04", {
                "sample_urls": [u.normalized_url for u in redirect_urls[:3]],
                "redirect_targets": [u.open_redirect_target for u in redirect_urls if u.open_redirect_target],
            }))

        suspicious_tld_urls = [u for u in url_results if u.has_suspicious_tld]
        if suspicious_tld_urls:
            findings.append(self._make_finding("URL-05", {
                "sample_urls": [u.normalized_url for u in suspicious_tld_urls[:3]],
                "tlds": list({u.suspicious_tld_name for u in suspicious_tld_urls if u.suspicious_tld_name}),
            }))

        userinfo_urls = [u for u in url_results if u.has_userinfo_spoof]
        if userinfo_urls:
            findings.append(self._make_finding("URL-06", {
                "sample_urls": [u.normalized_url for u in userinfo_urls[:3]],
                "userinfo": [u.userinfo for u in userinfo_urls if u.userinfo],
            }))

        length_entropy_urls = [u for u in url_results if u.total_length > 200 or u.entropy > 4.2]
        if length_entropy_urls:
            findings.append(self._make_finding("URL-08", {
                "sample_urls": [u.normalized_url for u in length_entropy_urls[:3]],
            }))

    @staticmethod
    def _make_finding(rule_id: str, evidence: dict[str, Any]) -> TriggeredFinding:
        rule_def = RULE_CATALOG[rule_id]
        effective = rule_def.base_weight * rule_def.confidence_multiplier
        return TriggeredFinding(
            rule_id=rule_id,
            rule_name=rule_def.rule_name,
            category=rule_def.category,
            severity=rule_def.severity,
            base_weight=rule_def.base_weight,
            confidence_multiplier=rule_def.confidence_multiplier,
            effective_score=round(effective, 2),
            description=rule_def.description,
            evidence_data=evidence,
            remediation_advice=rule_def.remediation_advice,
            mitre_attack_id=rule_def.mitre_attack_id,
        )

