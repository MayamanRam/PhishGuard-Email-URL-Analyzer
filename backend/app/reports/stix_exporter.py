"""OASIS STIX 2.1 Threat Intelligence Bundle Exporter.

Converts PhishGuard investigation findings, observable artifacts (senders, URLs, file hashes),
and MITRE ATT&CK mappings into standard OASIS STIX 2.1 JSON format for SIEM/SOAR ingestion.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid


class StixExporter:
    """Exports structured PhishGuard telemetry as an OASIS STIX 2.1 Bundle."""

    STIX_VERSION = "2.1"
    IDENTITY_ID = "identity--7a12b6e1-93c4-406e-821f-c0c1b75fa981"

    @classmethod
    def export_bundle(
        cls,
        title: str,
        target_identifier: str,
        risk_score: float,
        severity: str,
        findings: list[dict[str, Any]],
        summary_text: str = "",
        created_at: str | None = None,
    ) -> str:
        """Generate a valid STIX 2.1 JSON bundle string."""
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        timestamp_str = created_at or now_iso

        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: list[dict[str, Any]] = []

        # 1. Identity Object (Generating Engine)
        identity_obj = {
            "type": "identity",
            "spec_version": cls.STIX_VERSION,
            "id": cls.IDENTITY_ID,
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "name": "PhishGuard Threat Analysis Platform",
            "description": "Defensive Phishing Email and Static URL Analysis Engine",
            "identity_class": "system",
        }
        objects.append(identity_obj)

        # 2. Attack Patterns (Unique MITRE ATT&CK techniques)
        mitre_ids = set()
        for f in findings:
            mid = f.get("mitre_attack_id") or f.get("mitre_id")
            if mid and mid != "N/A":
                mitre_ids.add(mid)

        attack_pattern_map: dict[str, str] = {}
        for mid in sorted(mitre_ids):
            ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, f'mitre-{mid}')}"
            attack_pattern_map[mid] = ap_id
            objects.append({
                "type": "attack-pattern",
                "spec_version": cls.STIX_VERSION,
                "id": ap_id,
                "created": timestamp_str,
                "modified": timestamp_str,
                "name": f"Adversary Technique {mid}",
                "description": f"Phishing evasion or exploitation technique identified by PhishGuard (MITRE ATT&CK {mid}).",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": mid,
                        "url": f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/",
                    }
                ],
            })

        # 3. Indicator Objects & Relationships
        indicator_ids: list[str] = []

        # Target observable indicator
        is_url = "://" in target_identifier or target_identifier.startswith(("http", "hxxp"))
        is_email = "@" in target_identifier and not is_url

        if is_url:
            clean_url = target_identifier.replace("hxxp", "http").replace("[.]", ".")
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": cls.STIX_VERSION,
                "id": ind_id,
                "created": timestamp_str,
                "modified": timestamp_str,
                "name": f"Suspicious URL: {clean_url[:60]}",
                "description": f"Phishing or credential harvesting URL detected with risk score {risk_score:.1f}/100 ({severity.upper()}). {summary_text}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[url:value = '{clean_url}']",
                "pattern_type": "stix",
                "valid_from": timestamp_str,
                "confidence": min(100, int(risk_score)),
            })
        elif is_email:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)
            objects.append({
                "type": "indicator",
                "spec_version": cls.STIX_VERSION,
                "id": ind_id,
                "created": timestamp_str,
                "modified": timestamp_str,
                "name": f"Suspicious Sender: {target_identifier}",
                "description": f"Phishing sender identity detected with risk score {risk_score:.1f}/100. {summary_text}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[email-addr:value = '{target_identifier}']",
                "pattern_type": "stix",
                "valid_from": timestamp_str,
                "confidence": min(100, int(risk_score)),
            })

        # Findings Indicators (Files / Hashes / URLs inside findings)
        for f in findings:
            rule_id = f.get("rule_id", "GENERIC")
            rule_name = f.get("rule_name", "Phishing Indicator")
            evidence = f.get("evidence") or f.get("evidence_data") or {}
            mitre_id = f.get("mitre_attack_id") or f.get("mitre_id")

            # If evidence has sha256
            sha256 = evidence.get("sha256")
            if sha256 and len(str(sha256)) == 64:
                file_ind_id = f"indicator--{uuid.uuid4()}"
                indicator_ids.append(file_ind_id)
                objects.append({
                    "type": "indicator",
                    "spec_version": cls.STIX_VERSION,
                    "id": file_ind_id,
                    "created": timestamp_str,
                    "modified": timestamp_str,
                    "name": f"Malicious Attachment Hash: {sha256[:16]}...",
                    "description": f"Attachment associated with rule {rule_id}: {rule_name}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
                    "pattern_type": "stix",
                    "valid_from": timestamp_str,
                    "confidence": int(float(f.get("confidence_multiplier", 0.9)) * 100),
                })
                # Link to attack pattern if available
                if mitre_id and mitre_id in attack_pattern_map:
                    objects.append({
                        "type": "relationship",
                        "spec_version": cls.STIX_VERSION,
                        "id": f"relationship--{uuid.uuid4()}",
                        "created": timestamp_str,
                        "modified": timestamp_str,
                        "relationship_type": "indicates",
                        "source_ref": file_ind_id,
                        "target_ref": attack_pattern_map[mitre_id],
                    })

        # Link primary indicators to attack patterns
        for ind_id in indicator_ids:
            for ap_id in attack_pattern_map.values():
                objects.append({
                    "type": "relationship",
                    "spec_version": cls.STIX_VERSION,
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": timestamp_str,
                    "modified": timestamp_str,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                })

        # 4. Final STIX 2.1 Bundle Payload
        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        return json.dumps(stix_bundle, indent=2)

