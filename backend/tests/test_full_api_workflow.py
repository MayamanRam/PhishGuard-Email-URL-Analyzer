"""End-to-End API Workflow Integration Tests.

Validates email analysis, URL analysis, case management, report generation (JSON/CSV/PDF),
and audit trail logging across the REST API pipeline.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

CLIENT_HEADERS = {
    "X-PhishGuard-Client": "web-console",
    "Origin": "http://127.0.0.1:5173",
    "Host": "127.0.0.1:8000",
}


@pytest.mark.asyncio
async def test_full_api_investigation_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        # 1. Check overview stats initially
        res = await client.get("/api/v1/overview/stats", headers=CLIENT_HEADERS)
        assert res.status_code == 200
        stats = res.json()
        assert "total_analyses" in stats
        assert "severity_distribution" in stats

        # 2. Analyze a suspicious email via analyze-text
        raw_eml = (
            "From: \"PayPal Security\" <spoof@unauthorized-phish.ru>\r\n"
            "To: analyst@victim.org\r\n"
            "Subject: URGENT: Confirm your credentials\r\n"
            "Date: Thu, 12 Nov 2026 14:00:00 +0000\r\n"
            "Authentication-Results: mx.target.com; dkim=fail; spf=fail;\r\n"
            "\r\n"
            "Immediate wire transfer or account verification needed: http://192.168.1.100/paypal-verify\r\n"
        )

        email_res = await client.post(
            "/api/v1/emails/analyze-text",
            headers=CLIENT_HEADERS,
            json={"raw_email": raw_eml, "source_name": "test_phish.eml"},
        )
        assert email_res.status_code == 200
        email_data = email_res.json()
        email_run_id = email_data["run_id"]
        assert email_data["risk_score"] > 30.0
        assert len(email_data["findings"]) >= 1

        # 3. Retrieve the email analysis run by ID
        get_email_res = await client.get(f"/api/v1/emails/{email_run_id}", headers=CLIENT_HEADERS)
        assert get_email_res.status_code == 200
        assert get_email_res.json()["run_id"] == email_run_id

        # 4. Analyze a suspicious URL
        url_res = await client.post(
            "/api/v1/urls/analyze",
            headers=CLIENT_HEADERS,
            json={"url": "http://user:pass@192.168.1.200:8080/bank-login.php?redirect_uri=https://evil.ru"},
        )
        assert url_res.status_code == 200
        url_data = url_res.json()
        url_run_id = url_data["run_id"]
        assert url_data["risk_score"] > 20.0
        assert len(url_data["findings"]) >= 1

        # 5. Retrieve the URL analysis run by ID
        get_url_res = await client.get(f"/api/v1/urls/{url_run_id}", headers=CLIENT_HEADERS)
        assert get_url_res.status_code == 200
        assert get_url_res.json()["run_id"] == url_run_id

        # 6. Create an investigation case
        case_res = await client.post(
            "/api/v1/cases",
            headers=CLIENT_HEADERS,
            json={
                "title": "Incident 2026-11-12: PayPal Brand Impersonation Campaign",
                "description": "Suspicious email with literal IP link and authentication failure claims.",
                "severity": "high",
                "assigned_to": "Tier-2 SOC Analyst",
            },
        )
        assert case_res.status_code == 201
        case_id = case_res.json()["id"]

        # 7. Associate the email analysis run with the case
        assoc_res = await client.post(
            f"/api/v1/cases/{case_id}/artifacts",
            headers=CLIENT_HEADERS,
            json={"artifact_type": "analysis_run", "artifact_id": email_run_id},
        )
        assert assoc_res.status_code == 201

        # 8. Add an analyst note
        note_res = await client.post(
            f"/api/v1/cases/{case_id}/notes",
            headers=CLIENT_HEADERS,
            json={"content": "Confirmed IP 192.168.1.100 host is an unauthorized phishing landing target.", "author": "Analyst-42"},
        )
        assert note_res.status_code == 201

        # 9. Update case status to investigating
        patch_res = await client.patch(
            f"/api/v1/cases/{case_id}",
            headers=CLIENT_HEADERS,
            json={"status": "investigating", "severity": "critical"},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["status"] == "investigating"
        assert patch_res.json()["severity"] == "critical"

        # 10. Generate Reports (JSON, CSV, PDF)
        for fmt in ("json", "csv", "pdf"):
            rep_res = await client.post(
                "/api/v1/reports",
                headers=CLIENT_HEADERS,
                json={"format": fmt, "analysis_run_id": email_run_id},
            )
            assert rep_res.status_code == 201
            rep_data = rep_res.json()
            rep_id = rep_data["id"]

            # Download report file
            dl_res = await client.get(f"/api/v1/reports/{rep_id}/download", headers=CLIENT_HEADERS)
            assert dl_res.status_code == 200
            assert len(dl_res.content) > 0

        # 11. Check Rule Catalog and Findings Registry
        rules_res = await client.get("/api/v1/findings/rules", headers=CLIENT_HEADERS)
        assert rules_res.status_code == 200
        assert len(rules_res.json()) >= 24

        findings_res = await client.get("/api/v1/findings", headers=CLIENT_HEADERS)
        assert findings_res.status_code == 200
        assert findings_res.json()["total"] >= 1

        # 12. Check Audit Trail
        audit_res = await client.get("/api/v1/audit", headers=CLIENT_HEADERS)
        assert audit_res.status_code == 200
        actions = [a["event_type"] for a in audit_res.json()["items"]]
        assert "EMAIL_ANALYZED" in actions
        assert "URL_ANALYZED" in actions
        assert "CASE_CREATED" in actions
        assert "REPORT_GENERATED" in actions
