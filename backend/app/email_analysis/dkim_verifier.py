"""Air-Gapped DKIM Cryptographic Verification Engine.

RFC 6376 compliant offline DKIM verification using imported local DNS TXT cache snapshots.
Enforces zero-network air-gapped isolation: queries SQLite local cache, extracts RSA public keys,
canonicalizes headers and body, computes hashes, and verifies RSA-SHA256 / RSA-SHA1 cryptographic signatures.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.dkim_dns_record import DkimDnsRecord


@dataclass
class DkimVerificationResult:
    """Detailed result of an offline DKIM verification check."""
    status: str  # PASS, FAIL, NO_CACHE, NO_SIGNATURE, MALFORMED_HEADER, REVOKED, KEY_PARSE_ERROR
    verified: bool
    signing_domain: str | None = None
    selector: str | None = None
    algorithm: str | None = None
    canonicalization: str | None = None
    signed_headers: list[str] = field(default_factory=list)
    body_hash_status: str | None = None  # PASS, MISMATCH, NOT_CHECKED
    signature_status: str | None = None  # PASS, FAIL, NOT_CHECKED
    message: str = ""
    dns_source_snapshot: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "verified": self.verified,
            "signing_domain": self.signing_domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "signed_headers": self.signed_headers,
            "body_hash_status": self.body_hash_status,
            "signature_status": self.signature_status,
            "message": self.message,
            "dns_source_snapshot": self.dns_source_snapshot,
        }


class OfflineDkimVerifier:
    """RFC 6376 Offline Cryptographic DKIM Verifier backed by local DNS cache."""

    @classmethod
    def verify_message(
        cls,
        raw_eml: bytes,
        db: Session | None = None,
        cached_records: dict[tuple[str, str], str] | None = None,
    ) -> DkimVerificationResult:
        """Perform full offline DKIM cryptographic verification on raw RFC 5322 email bytes."""
        # 1. Normalize line endings to CRLF for RFC 6376 processing
        normalized_eml = raw_eml.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

        # 2. Split headers and body
        parts = normalized_eml.split(b"\r\n\r\n", 1)
        header_bytes = parts[0]
        body_bytes = parts[1] if len(parts) > 1 else b""

        # 3. Parse headers into list of (name, raw_header_field)
        headers = cls._parse_raw_headers(header_bytes)

        # 4. Find DKIM-Signature header
        dkim_header_field: str | None = None
        for name, field_str in reversed(headers):
            if name.lower() == "dkim-signature":
                dkim_header_field = field_str
                break

        if not dkim_header_field:
            return DkimVerificationResult(
                status="NO_SIGNATURE",
                verified=False,
                message="No DKIM-Signature header found in email message.",
            )

        # 5. Parse DKIM-Signature tags
        tags = cls._parse_dkim_tags(dkim_header_field)
        d = tags.get("d")
        s = tags.get("s")
        a = tags.get("a", "rsa-sha256").lower()
        c = tags.get("c", "simple/simple").lower()
        h_str = tags.get("h", "")
        bh = tags.get("bh", "")
        b = tags.get("b", "")

        if not d or not s or not b or not bh or not h_str:
            return DkimVerificationResult(
                status="MALFORMED_HEADER",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                message="DKIM-Signature header is missing required tags (d, s, b, bh, or h).",
            )

        signed_header_names = [h.strip().lower() for h in h_str.split(":") if h.strip()]

        # 6. Lookup public key from local air-gapped cache
        public_key_txt: str | None = None
        source_snapshot: str | None = None

        if cached_records is not None:
            public_key_txt = cached_records.get((d.lower(), s.lower()))
            source_snapshot = "in_memory_fixture"
        elif db is not None:
            stmt = select(DkimDnsRecord).where(
                DkimDnsRecord.domain == d.lower(),
                DkimDnsRecord.selector == s.lower(),
            )
            rec = db.scalar(stmt)
            if rec:
                public_key_txt = rec.public_key_txt
                source_snapshot = rec.source_snapshot

        if not public_key_txt:
            return DkimVerificationResult(
                status="NO_CACHE",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                canonicalization=c,
                signed_headers=signed_header_names,
                message=(
                    f"No offline DNS cache snapshot found for selector '{s}' under domain '{d}'. "
                    "Air-gapped isolation prohibits live external DNS queries."
                ),
            )

        # 7. Extract RSA public key from TXT record
        rsa_pub_key, key_err = cls._load_public_key_from_txt(public_key_txt)
        if key_err:
            return DkimVerificationResult(
                status="KEY_PARSE_ERROR" if "revoked" not in key_err.lower() else "REVOKED",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                dns_source_snapshot=source_snapshot,
                message=f"DKIM public key error: {key_err}",
            )

        # 8. Canonicalize body and verify body hash (bh)
        c_parts = c.split("/")
        c_body = c_parts[1] if len(c_parts) > 1 else "simple"
        c_header = c_parts[0] if len(c_parts) > 0 else "simple"

        canonical_body = cls._canonicalize_body(body_bytes, c_body)
        computed_bh = cls._compute_body_hash(canonical_body, a)
        clean_bh = re.sub(r"\s+", "", bh)

        if clean_bh != computed_bh:
            return DkimVerificationResult(
                status="FAIL",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                canonicalization=c,
                signed_headers=signed_header_names,
                body_hash_status="MISMATCH",
                signature_status="NOT_CHECKED",
                dns_source_snapshot=source_snapshot,
                message=f"DKIM body hash verification failed (claimed {clean_bh[:12]}... != computed {computed_bh[:12]}...). Body content was modified.",
            )

        # 9. Canonicalize headers and verify RSA signature (b)
        canonical_header_bytes = cls._canonicalize_headers(
            headers=headers,
            signed_header_names=signed_header_names,
            dkim_header_field=dkim_header_field,
            c_header=c_header,
        )

        clean_sig_b64 = re.sub(r"\s+", "", b)
        try:
            sig_bytes = base64.b64decode(clean_sig_b64)
        except Exception as e:
            return DkimVerificationResult(
                status="FAIL",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                canonicalization=c,
                signed_headers=signed_header_names,
                body_hash_status="PASS",
                signature_status="FAIL",
                dns_source_snapshot=source_snapshot,
                message=f"DKIM signature tag 'b' is not valid base64: {e}",
            )

        hash_algo = hashes.SHA256() if a.endswith("sha256") else hashes.SHA1()  # nosec B303 - RFC 6376 backward compatibility
        if rsa_pub_key is None:
            return DkimVerificationResult(
                status="KEY_PARSE_ERROR",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                message="DKIM public key is not initialized.",
            )
        try:
            rsa_pub_key.verify(sig_bytes, canonical_header_bytes, padding.PKCS1v15(), hash_algo)
            return DkimVerificationResult(
                status="PASS",
                verified=True,
                signing_domain=d,
                selector=s,
                algorithm=a,
                canonicalization=c,
                signed_headers=signed_header_names,
                body_hash_status="PASS",
                signature_status="PASS",
                dns_source_snapshot=source_snapshot,
                message=(
                    f"DKIM cryptographic verification PASSED offline. Valid RSA-{a.split('-')[-1].upper()} signature "
                    f"verified using local DNS cache record for {s}._domainkey.{d}."
                ),
            )
        except InvalidSignature:
            return DkimVerificationResult(
                status="FAIL",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                canonicalization=c,
                signed_headers=signed_header_names,
                body_hash_status="PASS",
                signature_status="FAIL",
                dns_source_snapshot=source_snapshot,
                message=(
                    f"DKIM RSA cryptographic signature verification FAILED. The digital signature does not match "
                    f"the header contents using cached public key {s}._domainkey.{d}."
                ),
            )
        except Exception as e:
            return DkimVerificationResult(
                status="FAIL",
                verified=False,
                signing_domain=d,
                selector=s,
                algorithm=a,
                canonicalization=c,
                signed_headers=signed_header_names,
                body_hash_status="PASS",
                signature_status="FAIL",
                dns_source_snapshot=source_snapshot,
                message=f"DKIM cryptographic evaluation error: {str(e)}",
            )

    # -------------------------------------------------------------
    # Internal RFC 6376 Helpers
    # -------------------------------------------------------------

    @staticmethod
    def _parse_raw_headers(header_bytes: bytes) -> list[tuple[str, str]]:
        """Parse raw RFC 5322 header section preserving case and folding."""
        header_text = header_bytes.decode("utf-8", errors="replace")
        lines = header_text.split("\r\n")
        headers: list[tuple[str, str]] = []
        current_name = ""
        current_field_lines: list[str] = []

        for line in lines:
            if not line:
                continue
            if line[0] in (" ", "\t") and current_field_lines:
                current_field_lines.append(line)
            else:
                if current_field_lines:
                    headers.append((current_name, "\r\n".join(current_field_lines)))
                    current_field_lines = []
                if ":" in line:
                    colon_idx = line.index(":")
                    current_name = line[:colon_idx].strip()
                    current_field_lines = [line]
                else:
                    current_name = ""

        if current_field_lines:
            headers.append((current_name, "\r\n".join(current_field_lines)))

        return headers

    @staticmethod
    def _parse_dkim_tags(dkim_field: str) -> dict[str, str]:
        """Parse tag=value pairs from a DKIM-Signature header field."""
        content = dkim_field
        if ":" in content:
            content = content.split(":", 1)[1]

        # Unfold lines
        unfolded = re.sub(r"\r?\n[ \t]+", " ", content)
        tags: dict[str, str] = {}
        for part in unfolded.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip()] = v.strip()
        return tags

    @staticmethod
    def _load_public_key_from_txt(txt_record: str) -> tuple[Any | None, str | None]:
        """Extract and instantiate RSA public key from a DNS TXT record."""
        # Clean quotes
        clean_txt = txt_record.strip().strip('"').strip("'")
        tags: dict[str, str] = {}
        for part in clean_txt.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip()] = v.strip()

        p_val = tags.get("p")
        if p_val is None or p_val == "":
            return None, "DKIM public key is revoked (empty p tag)."

        clean_p = re.sub(r"\s+", "", p_val)
        try:
            der_bytes = base64.b64decode(clean_p)
            pub_key = load_der_public_key(der_bytes)
            return pub_key, None
        except Exception as e:
            return None, f"Failed to load DER RSA public key: {e}"

    @staticmethod
    def _canonicalize_body(body_bytes: bytes, mode: str) -> bytes:
        """RFC 6376 Section 3.4.3 / 3.4.4 Canonicalize Body."""
        if not body_bytes:
            return b""

        text = body_bytes.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        if mode == "relaxed":
            processed_lines: list[str] = []
            for line in lines:
                # Remove all whitespace at end of line
                line = re.sub(r"[ \t]+$", "", line)
                # Reduce sequences of WSP to single SP
                line = re.sub(r"[ \t]+", " ", line)
                processed_lines.append(line)
            # Remove all trailing empty lines
            while processed_lines and processed_lines[-1] == "":
                processed_lines.pop()
            if not processed_lines:
                return b""
            return ("\r\n".join(processed_lines) + "\r\n").encode("utf-8")
        else:
            # Simple body canonicalization: trim trailing empty lines
            while lines and lines[-1] == "":
                lines.pop()
            if not lines:
                return b""
            return ("\r\n".join(lines) + "\r\n").encode("utf-8")

    @classmethod
    def _compute_body_hash(cls, canonical_body: bytes, algo: str) -> str:
        """Compute base64 SHA-256 or SHA-1 hash of canonicalized body."""
        if algo.endswith("sha1"):
            hasher = hashlib.sha1()  # nosec B324 - RFC 6376 backward compatibility
        else:
            hasher = hashlib.sha256()
        hasher.update(canonical_body)
        return base64.b64encode(hasher.digest()).decode("utf-8")

    @classmethod
    def _canonicalize_headers(
        cls,
        headers: list[tuple[str, str]],
        signed_header_names: list[str],
        dkim_header_field: str,
        c_header: str,
    ) -> bytes:
        """RFC 6376 Section 3.4.1 / 3.4.2 Canonicalize Headers."""
        canon_lines: list[bytes] = []

        # RFC 6376 5.4.2: match headers bottom-up
        available_headers = list(headers)

        for h_name in signed_header_names:
            matched_field: str | None = None
            for idx in range(len(available_headers) - 1, -1, -1):
                name, raw_field = available_headers[idx]
                if name.lower() == h_name:
                    matched_field = raw_field
                    available_headers.pop(idx)
                    break

            if matched_field:
                canon_lines.append(cls._canonicalize_single_header(matched_field, c_header))

        # Canonicalize the DKIM-Signature header itself (without b= value)
        canon_dkim = cls._canonicalize_dkim_signature_header(dkim_header_field, c_header)
        canon_lines.append(canon_dkim)

        return b"".join(canon_lines)

    @staticmethod
    def _canonicalize_single_header(raw_field: str, mode: str) -> bytes:
        """Canonicalize one header line according to simple or relaxed mode."""
        if mode == "relaxed":
            if ":" not in raw_field:
                return (raw_field.strip() + "\r\n").encode("utf-8")
            name, val = raw_field.split(":", 1)
            lower_name = name.strip().lower()
            # Unfold and collapse whitespace
            unfolded_val = re.sub(r"\r?\n[ \t]+", " ", val)
            collapsed_val = re.sub(r"[ \t]+", " ", unfolded_val).strip()
            return f"{lower_name}:{collapsed_val}\r\n".encode("utf-8")
        else:
            # Simple header: preserve case and inner whitespace, ensure CRLF
            normalized = re.sub(r"\r?\n", "\r\n", raw_field).rstrip("\r\n") + "\r\n"
            return normalized.encode("utf-8")

    @classmethod
    def _canonicalize_dkim_signature_header(cls, dkim_field: str, mode: str) -> bytes:
        """Canonicalize DKIM-Signature header with b= tag value treated as empty string."""
        # Replace b=<val> with b=
        # Preserve everything else up to b= tag
        b_pattern = re.compile(r"b\s*=\s*([^;]*)")
        stripped_field = b_pattern.sub("b=", dkim_field)

        if mode == "relaxed":
            if ":" not in stripped_field:
                return stripped_field.strip().encode("utf-8")
            name, val = stripped_field.split(":", 1)
            lower_name = name.strip().lower()
            unfolded_val = re.sub(r"\r?\n[ \t]+", " ", val)
            collapsed_val = re.sub(r"[ \t]+", " ", unfolded_val).strip()
            # RFC 6376: final CRLF is NOT appended to DKIM-Signature header during signing
            return f"{lower_name}:{collapsed_val}".encode("utf-8")
        else:
            normalized = re.sub(r"\r?\n", "\r\n", stripped_field).rstrip("\r\n")
            return normalized.encode("utf-8")
