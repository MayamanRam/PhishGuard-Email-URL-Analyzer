"""Email Authentication Header Claims Auditor.

Parses Authentication-Results, Received-SPF, and DKIM-Signature headers.
Explicitly flags all claims as 'unverified header claims' because headers on an
untrusted incoming message could be fabricated by an upstream adversary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

from app.email_analysis.dkim_verifier import OfflineDkimVerifier


@dataclass
class SPFClaim:
    result: str  # pass, fail, softfail, neutral, none, temperror, permerror, missing
    sender_domain: str | None
    client_ip: str | None
    raw_claim: str


@dataclass
class DKIMClaim:
    result: str  # pass, fail, neutral, none, missing
    signing_domain: str | None  # d=
    selector: str | None  # s=
    raw_claim: str


@dataclass
class DMARCClaim:
    result: str  # pass, fail, none, missing
    header_from_domain: str | None
    action_taken: str | None  # reject, quarantine, none
    raw_claim: str


@dataclass
class AuthenticationAuditReport:
    spf: SPFClaim
    dkim: DKIMClaim
    dmarc: DMARCClaim
    is_unverified_header_claim: bool
    summary_verdict: str
    warnings: list[str]
    disclaimer: str
    dkim_offline_verification: dict[str, Any] | None = None


class EmailAuthenticationAuditor:
    """Audits email authentication headers with defensive skepticism."""

    DISCLAIMER = (
        "NOTE: Authentication claims reflect header claims recorded in the submitted message. "
        "In offline forensic analysis, external DNS TXT and cryptographic keys cannot be queried, "
        "so these are treated as unverified header claims rather than authoritative validation."
    )

    def audit(
        self,
        auth_results_headers: list[str],
        received_spf_headers: list[str] | None = None,
        all_headers: dict[str, list[str]] | None = None,
        raw_eml: bytes | None = None,
        db: Session | None = None,
        cached_records: dict[tuple[str, str], str] | None = None,
    ) -> AuthenticationAuditReport:
        """Parse authentication claims from Authentication-Results and Received-SPF headers."""
        received_spf_headers = received_spf_headers or []
        all_headers = all_headers or {}

        combined_auth_text = " ".join(auth_results_headers).lower()
        combined_spf_text = " ".join(received_spf_headers).lower()

        # Parse SPF
        spf_claim = self._parse_spf(combined_auth_text, combined_spf_text)

        # Parse DKIM
        dkim_claim = self._parse_dkim(combined_auth_text, all_headers.get("dkim-signature", []))

        # Parse DMARC
        dmarc_claim = self._parse_dmarc(combined_auth_text)

        warnings: list[str] = []
        dkim_offline_dict: dict[str, Any] | None = None
        is_unverified = True

        # Perform offline DKIM verification if raw email bytes are provided
        if raw_eml:
            dkim_res = OfflineDkimVerifier.verify_message(
                raw_eml=raw_eml,
                db=db,
                cached_records=cached_records,
            )
            dkim_offline_dict = dkim_res.to_dict()

            if dkim_res.status == "PASS":
                dkim_claim.result = "pass"
                is_unverified = False
                warnings.append(
                    f"Offline DKIM cryptographic verification PASSED for {dkim_res.selector}._domainkey.{dkim_res.signing_domain}"
                )
            elif dkim_res.status == "FAIL":
                dkim_claim.result = "fail"
                warnings.append(
                    f"Offline DKIM cryptographic verification FAILED: {dkim_res.message}"
                )
            elif dkim_res.status == "NO_CACHE":
                warnings.append(dkim_res.message)

        if spf_claim.result in ("fail", "softfail"):
            warnings.append(f"Header claims SPF {spf_claim.result.upper()} for domain '{spf_claim.sender_domain or 'unknown'}'")
        elif spf_claim.result == "missing":
            warnings.append("No SPF authentication claim found in headers")

        if dkim_claim.result == "fail":
            warnings.append(f"Header claims DKIM verification FAILED for domain '{dkim_claim.signing_domain or 'unknown'}'")
        elif dkim_claim.result == "missing":
            warnings.append("No DKIM authentication claim found in headers")

        if dmarc_claim.result == "fail":
            warnings.append(f"Header claims DMARC policy check FAILED (action: {dmarc_claim.action_taken or 'none'})")
        elif dmarc_claim.result == "missing":
            warnings.append("No DMARC evaluation claim found in headers")

        # Determine summary verdict
        if dkim_offline_dict and dkim_offline_dict.get("status") == "FAIL":
            verdict = "Authentication Failure (DKIM Cryptographic Check Failed)"
        elif dmarc_claim.result == "fail" or (spf_claim.result == "fail" and dkim_claim.result == "fail"):
            verdict = "Authentication Failure Claimed"
        elif dkim_offline_dict and dkim_offline_dict.get("status") == "PASS":
            verdict = "Authentication Pass Verified (Offline DKIM Validated)"
        elif spf_claim.result == "pass" or dkim_claim.result == "pass":
            verdict = "Authentication Pass Claimed (Unverified)"
        elif spf_claim.result == "softfail":
            verdict = "Suspicious Authentication Claim (SoftFail)"
        else:
            verdict = "Authentication Claims Inconclusive or Missing"

        return AuthenticationAuditReport(
            spf=spf_claim,
            dkim=dkim_claim,
            dmarc=dmarc_claim,
            is_unverified_header_claim=is_unverified,
            summary_verdict=verdict,
            warnings=warnings,
            disclaimer=self.DISCLAIMER,
            dkim_offline_verification=dkim_offline_dict,
        )

    def _parse_spf(self, auth_text: str, spf_text: str) -> SPFClaim:
        result = "missing"
        domain: str | None = None
        ip: str | None = None
        raw = ""

        # Check Received-SPF header first
        if spf_text:
            raw = spf_text
            match = re.search(r"^(pass|fail|softfail|neutral|none|temperror|permerror)\b", spf_text)
            if match:
                result = match.group(1)
            dom_match = re.search(r"identity=mailfrom;\s+envelope-from=([^\s;]+)", spf_text) or re.search(
                r"domain of ([^\s]+)", spf_text
            )
            if dom_match:
                domain = dom_match.group(1).lstrip("<").rstrip(">")
            ip_match = re.search(r"client-ip=([^\s;]+)", spf_text)
            if ip_match:
                ip = ip_match.group(1)

        # Check Authentication-Results if not resolved
        if result == "missing" and auth_text:
            match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", auth_text)
            if match:
                result = match.group(1)
                raw = match.group(0)
            dom_match = re.search(r"smtp\.mailfrom=([^\s;]+)", auth_text)
            if dom_match:
                domain = dom_match.group(1)

        return SPFClaim(
            result=result,
            sender_domain=domain,
            client_ip=ip,
            raw_claim=raw or "No SPF header claim",
        )

    def _parse_dkim(self, auth_text: str, dkim_signatures: list[str]) -> DKIMClaim:
        result = "missing"
        signing_domain: str | None = None
        selector: str | None = None
        raw = ""

        if auth_text:
            match = re.search(r"dkim=(pass|fail|neutral|none)", auth_text)
            if match:
                result = match.group(1)
                raw = match.group(0)
            dom_match = re.search(r"header\.d=([^\s;]+)", auth_text)
            if dom_match:
                signing_domain = dom_match.group(1)
            sel_match = re.search(r"header\.s=([^\s;]+)", auth_text)
            if sel_match:
                selector = sel_match.group(1)

        if not signing_domain and dkim_signatures:
            first_sig = dkim_signatures[0]
            d_match = re.search(r"d=([^\s;]+)", first_sig)
            if d_match:
                signing_domain = d_match.group(1)
            s_match = re.search(r"s=([^\s;]+)", first_sig)
            if s_match:
                selector = s_match.group(1)
            if result == "missing":
                result = "present_unverified"

        return DKIMClaim(
            result=result,
            signing_domain=signing_domain,
            selector=selector,
            raw_claim=raw or "No DKIM header claim",
        )

    def _parse_dmarc(self, auth_text: str) -> DMARCClaim:
        result = "missing"
        domain: str | None = None
        action: str | None = None
        raw = ""

        if auth_text:
            match = re.search(r"dmarc=(pass|fail|none)", auth_text)
            if match:
                result = match.group(1)
                raw = match.group(0)
            dom_match = re.search(r"header\.from=([^\s;]+)", auth_text)
            if dom_match:
                domain = dom_match.group(1)
            act_match = re.search(r"action=([^\s;]+)", auth_text)
            if act_match:
                action = act_match.group(1)

        return DMARCClaim(
            result=result,
            header_from_domain=domain,
            action_taken=action,
            raw_claim=raw or "No DMARC header claim",
        )

