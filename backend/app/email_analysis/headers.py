"""Email Header & In-Transit Hop Routing Engine.

Parses Received: headers, computes inter-hop transit delays, identifies IP types,
and inspects sender identity alignments (From, Reply-To, Return-Path, Sender).
"""

from __future__ import annotations

import email.utils
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class RoutingHop:
    hop_number: int
    raw_header: str
    from_host: str
    by_host: str
    with_protocol: str
    ip_address: str | None
    is_private_ip: bool
    timestamp_raw: str
    timestamp_utc: str | None
    delay_seconds: float | None
    anomalies: list[str]


@dataclass
class SenderIdentityAnalysis:
    from_display_name: str
    from_address: str
    from_domain: str
    reply_to_address: str | None
    reply_to_domain: str | None
    return_path_address: str | None
    return_path_domain: str | None
    sender_address: str | None
    sender_domain: str | None
    has_from_reply_to_mismatch: bool
    has_from_return_path_mismatch: bool
    has_display_name_email_spoofing: bool
    has_brand_impersonation_in_name: bool
    detected_impersonated_brand: str | None
    anomalies: list[str]


class EmailHeaderAnalyzer:
    """Defensive header and routing hop analyzer."""

    IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
    EMAIL_IN_STRING_REGEX = re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        re.IGNORECASE,
    )

    HIGH_PROFILE_BRANDS = [
        "paypal", "microsoft", "office365", "google", "apple", "netflix",
        "amazon", "chase", "wellsfargo", "bankofamerica", "docusign",
        "dhl", "fedex", "usps", "dropbox", "meta", "facebook", "linkedin",
    ]

    EXECUTIVE_KEYWORDS = [
        "ceo", "chief executive", "cfo", "director", "payroll", "human resources",
        "it support", "helpdesk", "security team", "admin", "administrator",
    ]

    def analyze_routing_hops(self, received_headers: list[str]) -> list[RoutingHop]:
        """Analyze Received headers chronologically (earliest hop at index 0).

        In standard email transit, the originating MTA is at the bottom of the header list,
        and subsequent relays prepend Received headers.
        """
        # Reverse to get chronological order (earliest first)
        chronological_headers = list(reversed(received_headers))
        hops: list[RoutingHop] = []
        prev_dt: datetime | None = None

        for idx, raw_header in enumerate(chronological_headers, start=1):
            normalized = " ".join(raw_header.split())
            from_host = self._extract_field(normalized, r"from\s+([^\s;()]+)")
            by_host = self._extract_field(normalized, r"by\s+([^\s;()]+)")
            with_proto = self._extract_field(normalized, r"with\s+([^\s;()]+)")

            ip_str = self._extract_ip(normalized)
            is_private = False
            if ip_str:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                except ValueError:
                    ip_str = None

            # Extract timestamp (usually after semicolon)
            timestamp_raw = ""
            timestamp_utc: str | None = None
            delay_seconds: float | None = None
            current_dt: datetime | None = None
            anomalies: list[str] = []

            if ";" in normalized:
                timestamp_raw = normalized.split(";")[-1].strip()
                try:
                    parsed_tuple = email.utils.parsedate_to_datetime(timestamp_raw)
                    if parsed_tuple:
                        current_dt = parsed_tuple.astimezone(timezone.utc)
                        timestamp_utc = current_dt.isoformat()
                except Exception:
                    anomalies.append("Unparseable hop timestamp")

            if current_dt and prev_dt:
                diff = (current_dt - prev_dt).total_seconds()
                delay_seconds = max(0.0, diff)
                if diff < -60:  # Negative delay indicates clock skew or forgery
                    anomalies.append(f"Clock skew / timestamp inversion ({diff:.0f}s)")
            elif current_dt:
                delay_seconds = 0.0

            if current_dt:
                prev_dt = current_dt

            if not from_host and not ip_str:
                anomalies.append("Missing relay source host and IP")

            hops.append(
                RoutingHop(
                    hop_number=idx,
                    raw_header=raw_header,
                    from_host=from_host or "unknown",
                    by_host=by_host or "unknown",
                    with_protocol=with_proto or "unknown",
                    ip_address=ip_str,
                    is_private_ip=is_private,
                    timestamp_raw=timestamp_raw,
                    timestamp_utc=timestamp_utc,
                    delay_seconds=delay_seconds,
                    anomalies=anomalies,
                )
            )

        return hops

    def analyze_sender_identities(
        self,
        from_header: str,
        reply_to_header: str | None = None,
        return_path_header: str | None = None,
        sender_header: str | None = None,
    ) -> SenderIdentityAnalysis:
        """Inspect From, Reply-To, Return-Path, and Sender headers for spoofing anomalies."""
        from_disp, from_addr = email.utils.parseaddr(from_header or "")
        reply_disp, reply_addr = email.utils.parseaddr(reply_to_header or "")
        rp_disp, rp_addr = email.utils.parseaddr(return_path_header or "")
        send_disp, send_addr = email.utils.parseaddr(sender_header or "")

        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else None
        rp_domain = rp_addr.split("@")[-1].lower() if "@" in rp_addr else None
        send_domain = send_addr.split("@")[-1].lower() if "@" in send_addr else None

        anomalies: list[str] = []

        # Check From vs Reply-To mismatch
        has_reply_mismatch = False
        if reply_domain and from_domain and reply_domain != from_domain:
            has_reply_mismatch = True
            anomalies.append(f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'")

        # Check From vs Return-Path mismatch
        has_rp_mismatch = False
        if rp_domain and from_domain and rp_domain != from_domain:
            has_rp_mismatch = True
            anomalies.append(f"Return-Path domain '{rp_domain}' differs from From domain '{from_domain}'")

        # Check display name spoofing (email embedded in display name)
        has_disp_email_spoof = False
        found_emails_in_disp = self.EMAIL_IN_STRING_REGEX.findall(from_disp)
        if found_emails_in_disp:
            embedded_email = found_emails_in_disp[0].lower()
            if embedded_email != from_addr.lower():
                has_disp_email_spoof = True
                anomalies.append(
                    f"Display name contains address '{embedded_email}' which differs from actual sender '{from_addr}'"
                )

        # Check brand impersonation in display name
        has_brand_impersonation = False
        detected_brand: str | None = None
        disp_lower = from_disp.lower()
        for brand in self.HIGH_PROFILE_BRANDS:
            if brand in disp_lower and brand not in from_domain:
                has_brand_impersonation = True
                detected_brand = brand
                anomalies.append(
                    f"Display name references '{brand.capitalize()}' but sender domain is '{from_domain}'"
                )
                break

        return SenderIdentityAnalysis(
            from_display_name=from_disp,
            from_address=from_addr,
            from_domain=from_domain,
            reply_to_address=reply_addr if reply_addr else None,
            reply_to_domain=reply_domain,
            return_path_address=rp_addr if rp_addr else None,
            return_path_domain=rp_domain,
            sender_address=send_addr if send_addr else None,
            sender_domain=send_domain,
            has_from_reply_to_mismatch=has_reply_mismatch,
            has_from_return_path_mismatch=has_rp_mismatch,
            has_display_name_email_spoofing=has_disp_email_spoof,
            has_brand_impersonation_in_name=has_brand_impersonation,
            detected_impersonated_brand=detected_brand,
            anomalies=anomalies,
        )

    @staticmethod
    def _extract_field(text: str, pattern: str) -> str:
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_ip(self, text: str) -> str | None:
        ipv4_matches = self.IPV4_REGEX.findall(text)
        if ipv4_matches:
            for candidate in ipv4_matches:
                parts = candidate.split(".")
                if all(0 <= int(p) <= 255 for p in parts):
                    return candidate
        ipv6_matches = self.IPV6_REGEX.findall(text)
        if ipv6_matches:
            return ipv6_matches[0]
        return None

