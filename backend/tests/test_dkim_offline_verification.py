"""Unit and Integration Tests for Air-Gapped DKIM Verification and DNS Cache."""

from __future__ import annotations

import base64
import json
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.email_analysis.dkim_verifier import OfflineDkimVerifier
from app.models.dkim_dns_record import DkimDnsRecord


def _generate_test_dkim_pair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pub_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    return priv, f"v=DKIM1; k=rsa; p={pub_b64}"


def _build_signed_email(
    priv_key,
    domain: str = "secure.corp",
    selector: str = "s1",
    subject: str = "Quarterly Report",
    body: str = "Please find the requested quarterly financial report attached.\r\n",
    tamper_body: str | None = None,
    tamper_subject: str | None = None,
) -> tuple[bytes, str]:
    # 1. Canonicalize body (relaxed)
    body_clean = body.replace("\r\n", "\n").replace("\n", "\r\n")
    lines = [re.sub(r"[ \t]+", " ", re.sub(r"[ \t]+$", "", line)) for line in body_clean.split("\r\n")]
    while lines and lines[-1] == "":
        lines.pop()
    canon_body = ("\r\n".join(lines) + "\r\n").encode("utf-8") if lines else b""

    hasher = hashlib = __import__("hashlib").sha256()
    hasher.update(canon_body)
    bh = base64.b64encode(hasher.digest()).decode("ascii")

    # 2. Header lines
    h_from = f"from:security@{domain}\r\n"
    h_to = "to:analyst@company.com\r\n"
    h_subj = f"subject:{subject}\r\n"
    h_date = "date:Fri, 13 Nov 2026 12:00:00 +0000\r\n"

    headers_to_sign = ["from", "to", "subject", "date"]
    dkim_sig_pre = (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; "
        f"h=from:to:subject:date; bh={bh}; b="
    )
    canon_dkim = f"dkim-signature:{dkim_sig_pre}".encode("utf-8")

    # 3. Concatenate canonical headers for signing
    signed_bytes = (h_from + h_to + h_subj + h_date).encode("utf-8") + canon_dkim
    sig = priv_key.sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())
    b_val = base64.b64encode(sig).decode("ascii")

    final_dkim_header = f"DKIM-Signature: {dkim_sig_pre}{b_val}\r\n"

    # Assemble raw message (apply tamper if requested)
    actual_subj = tamper_subject or subject
    actual_body = tamper_body or body

    raw_eml = (
        f"From: security@{domain}\r\n"
        f"To: analyst@company.com\r\n"
        f"Subject: {actual_subj}\r\n"
        f"Date: Fri, 13 Nov 2026 12:00:00 +0000\r\n"
        f"{final_dkim_header}"
        f"\r\n"
        f"{actual_body}"
    ).encode("utf-8")

    return raw_eml, b_val


def test_dkim_no_signature():
    eml = b"From: user@example.com\r\nSubject: Hello\r\n\r\nTest body"
    res = OfflineDkimVerifier.verify_message(eml)
    assert res.status == "NO_SIGNATURE"
    assert res.verified is False


def test_dkim_no_cache():
    eml = (
        b"From: user@corp.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=corp.com; s=s2026; h=from; bh=abc=; b=def=\r\n\r\n"
        b"Test body"
    )
    res = OfflineDkimVerifier.verify_message(eml, cached_records={})
    assert res.status == "NO_CACHE"
    assert res.verified is False
    assert "air-gapped" in res.message.lower()


def test_dkim_revoked_key():
    eml = (
        b"From: user@corp.com\r\n"
        b"DKIM-Signature: v=1; a=rsa-sha256; d=corp.com; s=s2026; h=from; bh=abc=; b=def=\r\n\r\n"
        b"Test body"
    )
    # Revoked key has empty p=
    cache = {("corp.com", "s2026"): "v=DKIM1; k=rsa; p="}
    res = OfflineDkimVerifier.verify_message(eml, cached_records=cache)
    assert res.status == "REVOKED"
    assert res.verified is False


def test_dkim_offline_cryptographic_verification_pass():
    priv, txt_record = _generate_test_dkim_pair()
    raw_eml, _ = _build_signed_email(priv, domain="secure.corp", selector="s1")

    cache = {("secure.corp", "s1"): txt_record}
    res = OfflineDkimVerifier.verify_message(raw_eml, cached_records=cache)

    assert res.status == "PASS"
    assert res.verified is True
    assert res.body_hash_status == "PASS"
    assert res.signature_status == "PASS"


def test_dkim_tampered_body_fails_body_hash():
    priv, txt_record = _generate_test_dkim_pair()
    raw_eml, _ = _build_signed_email(
        priv,
        domain="secure.corp",
        selector="s1",
        tamper_body="TAMPERED: Wire $100,000 to adversary account!\r\n",
    )

    cache = {("secure.corp", "s1"): txt_record}
    res = OfflineDkimVerifier.verify_message(raw_eml, cached_records=cache)

    assert res.status == "FAIL"
    assert res.verified is False
    assert res.body_hash_status == "MISMATCH"
    assert "body content was modified" in res.message.lower()


def test_dkim_tampered_header_fails_signature():
    priv, txt_record = _generate_test_dkim_pair()
    raw_eml, _ = _build_signed_email(
        priv,
        domain="secure.corp",
        selector="s1",
        tamper_subject="URGENT: Password Reset Required",
    )

    cache = {("secure.corp", "s1"): txt_record}
    res = OfflineDkimVerifier.verify_message(raw_eml, cached_records=cache)

    assert res.status == "FAIL"
    assert res.verified is False
    assert res.signature_status == "FAIL"
    assert "digital signature does not match" in res.message.lower()


def test_dkim_cache_api_endpoints(client: TestClient):
    _, txt_record = _generate_test_dkim_pair()

    headers = {"X-PhishGuard-Client": "web-console"}

    # 1. Import snapshot
    import_payload = {
        "source_snapshot": "corporate_zone_2026.json",
        "records": [
            {
                "domain": "trusted-partner.org",
                "selector": "dkim1",
                "public_key_txt": txt_record,
                "notes": "Verified partner zone snapshot",
            }
        ],
    }
    resp = client.post("/api/v1/dkim-cache/import", json=import_payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["imported"] == 1

    # 2. List records
    list_resp = client.get("/api/v1/dkim-cache?domain=trusted-partner.org", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()["items"]
    assert len(items) == 1
    rec_id = items[0]["id"]
    assert items[0]["domain"] == "trusted-partner.org"
    assert items[0]["selector"] == "dkim1"

    # 3. Delete record
    del_resp = client.delete(f"/api/v1/dkim-cache/{rec_id}", headers=headers)
    assert del_resp.status_code == 200
    assert "Deleted DKIM record" in del_resp.json()["message"]

    # 4. Verify gone
    list_resp2 = client.get("/api/v1/dkim-cache?domain=trusted-partner.org", headers=headers)
    assert list_resp2.json()["total"] == 0
