# REST API Specification (API_SPECIFICATION.md) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Global API Standards & Security Headers

- **Base URL:** `http://127.0.0.1:8000/api/v1`
- **Protocol:** HTTP/1.1 (loopback-bound, TLS-terminable behind reverse proxy)
- **Content Negotiation:** `Accept: application/json`
- **Mandatory Custom CSRF Header:** All state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) require:
  ```http
  X-PhishGuard-Client: web-console
  ```
- **Rate Limiting:** Sliding-window rate limiter (default: 60 requests/minute per IP).
  - Headers returned on every response:
    - `X-RateLimit-Limit: 60`
    - `X-RateLimit-Remaining: <count>`
    - `X-RateLimit-Reset: <epoch_seconds>`

---

### 2. Endpoints Catalog

#### 2.1 System Health Probe
- **Endpoint:** `GET /api/v1/health`
- **Description:** Verifies loopback API availability and SQLite database connectivity.
- **Response (200 OK):**
```json
{
  "status": "healthy",
  "app_name": "PhishGuard Phishing Threat Analysis Platform",
  "version": "1.0.0",
  "timestamp": "2026-11-13T12:00:00Z",
  "database": {
    "status": "connected",
    "error": null
  },
  "environment": "development"
}
```

#### 2.2 SOC Dashboard Overview
- **Endpoint:** `GET /api/v1/overview/stats`
- **Description:** Aggregates SOC triage metrics, severity counts, and recent scans.
- **Response (200 OK):**
```json
{
  "total_analyses": 142,
  "email_analyses": 98,
  "url_analyses": 44,
  "open_cases": 12,
  "total_findings": 387,
  "severity_distribution": {
    "low": 45,
    "moderate": 52,
    "high": 31,
    "critical": 14
  },
  "recent_analyses": [
    {
      "id": "7b82798f-0a44-42f0-9ef2-a2798e1f5791",
      "target_type": "email",
      "target_identifier": "Immediate Password Verification Required",
      "risk_score": 88.5,
      "severity": "critical",
      "created_at": "2026-11-13T11:45:00Z"
    }
  ]
}
```

#### 2.3 Email Ingestion & Analysis (Multipart Upload)
- **Endpoint:** `POST /api/v1/emails/analyze`
- **Headers:** `X-PhishGuard-Client: web-console`
- **Content-Type:** `multipart/form-data`
- **Form Data:** `file`: Binary `.eml` or `.msg` stream (enforced $< 10$ MB).
- **Response (200 OK):**
```json
{
  "run_id": "9d81f2c2-8411-4091-bf91-b3b320d36711",
  "target_type": "email",
  "subject": "Immediate Account Verification Required",
  "risk_score": 89.2,
  "severity": "critical",
  "formula_explanation": "Critical Risk (89.2/100): High-confidence multi-category threats detected.",
  "category_scores": {
    "header_routing": 12.5,
    "sender_spoofing": 24.8,
    "auth_claims": 20.0,
    "url_threats": 22.4,
    "attachment_risk": 9.5,
    "content_evasion": 0.0
  },
  "category_details": [
    {
      "category": "sender_spoofing",
      "category_cap": 30.0,
      "raw_rule_sum": 36.0,
      "diminishing_score": 24.8,
      "rules_triggered_count": 2
    }
  ],
  "findings": [
    {
      "rule_id": "SPOOF-001",
      "rule_name": "From vs Reply-To Domain Mismatch",
      "category": "sender_spoofing",
      "severity": "high",
      "effective_score": 18.0,
      "evidence": { "from_domain": "paypal.com", "reply_to_domain": "scammer.xyz" },
      "remediation": "Investigate destination relay mailbox.",
      "mitre_id": "T1566.001"
    }
  ],
  "email_metadata": {
    "sha256": "4b92d8f921...",
    "from": "\"PayPal Security\" <service@unauthorized.ru>",
    "to": "victim@target.org",
    "date": "2026-11-13T11:30:00Z",
    "sender_analysis": {
      "from_display_name": "PayPal Security",
      "from_address": "service@unauthorized.ru",
      "from_domain": "unauthorized.ru",
      "has_from_reply_to_mismatch": true,
      "has_display_name_email_spoofing": true,
      "has_brand_impersonation_in_name": true,
      "detected_impersonated_brand": "PayPal"
    },
    "auth_report": {
      "spf": { "result": "fail", "sender_domain": "unauthorized.ru" },
      "dkim": { "result": "fail" },
      "dmarc": { "result": "fail", "action_taken": "reject" },
      "verdict": "fail",
      "disclaimer": "Unverified Header Claim — Preserved for Forensic Context Only"
    },
    "routing_hops": []
  },
  "extracted_urls": [],
  "attachments": [],
  "created_at": "2026-11-13T11:45:00Z"
}
```

#### 2.4 Email Analysis (Pasted Raw Text)
- **Endpoint:** `POST /api/v1/emails/analyze-text`
- **Headers:** `X-PhishGuard-Client: web-console`, `Content-Type: application/json`
- **Request Body:**
```json
{
  "raw_email": "From: \"PayPal Support\" <scam@evil.com>\nTo: ...",
  "source_name": "pasted_email.eml"
}
```

#### 2.5 Static URL Analysis
- **Endpoint:** `POST /api/v1/urls/analyze`
- **Headers:** `X-PhishGuard-Client: web-console`, `Content-Type: application/json`
- **Request Body:**
```json
{
  "url": "https://xn--pple-43d.com/login-verification?token=sec_994"
}
```
- **Response (200 OK):**
```json
{
  "run_id": "11ab3cde-f123-4567-89ab-cdef01234567",
  "target_type": "url",
  "url": "https://xn--pple-43d.com/login-verification?token=sec_994",
  "risk_score": 74.5,
  "severity": "high",
  "formula_explanation": "High Risk (74.5/100): Strong evasion signals present.",
  "category_scores": { "url_threats": 27.5 },
  "findings": [
    {
      "rule_id": "URL-002",
      "rule_name": "Punycode IDN Domain Detected",
      "category": "url_threats",
      "severity": "high",
      "effective_score": 20.0,
      "evidence": { "hostname": "xn--pple-43d.com", "decoded": "аpple.com" },
      "remediation": "Do not visit. Treat as visual homoglyph spoof.",
      "mitre_id": "T1566.002"
    }
  ],
  "url_analysis": {
    "original_url": "https://xn--pple-43d.com/login-verification?token=sec_994",
    "normalized_url": "https://xn--pple-43d.com/login-verification?token=sec_994",
    "scheme": "https",
    "hostname": "xn--pple-43d.com",
    "registrable_domain": "xn--pple-43d.com",
    "public_suffix": "com",
    "has_ip_hostname": false,
    "is_punycode": true,
    "decoded_punycode_host": "аpple.com",
    "has_mixed_script_homoglyphs": true,
    "has_brand_impersonation": true,
    "impersonated_brand_name": "Apple",
    "entropy": 3.84,
    "total_length": 58,
    "anomalies": ["Punycode encoded host", "Mixed Cyrillic homoglyph"]
  },
  "created_at": "2026-11-13T11:45:00Z"
}
```

#### 2.6 Investigation Cases
- **`GET /api/v1/cases`**: Query cases with optional `?status=` and `?severity=`.
- **`POST /api/v1/cases`**: Initialize case.
- **`GET /api/v1/cases/{case_id}`**: Fetch case details with chronological notes and linked artifacts.
- **`PATCH /api/v1/cases/{case_id}`**: Mutate status, severity, or assignee.
- **`POST /api/v1/cases/{case_id}/notes`**: Append analyst observation.
- **`POST /api/v1/cases/{case_id}/artifacts`**: Associate artifact or analysis run ID.

#### 2.7 Reports & Exports
- **`POST /api/v1/reports`**: Generate PDF, CSV, JSON, or STIX 2.1 threat report for an analysis run or case (`format`: `"pdf" | "csv" | "json" | "stix"`).
- **`GET /api/v1/reports`**: List generated report registry.
- **`GET /api/v1/reports/{report_id}/download`**: Stream report file with safe headers and path traversal shielding (`application/stix+json;version=2.1` for STIX bundles).

#### 2.8 Air-Gapped DKIM DNS Cache
- **`POST /api/v1/dkim-cache/import`**: Bulk import or update DNS TXT zone snapshots containing RSA public keys (`v=DKIM1; p=...`) for offline cryptographic signature verification.
- **`GET /api/v1/dkim-cache`**: Query cached DKIM DNS records with optional `?domain=` filter.
- **`DELETE /api/v1/dkim-cache/{record_id}`**: Delete a cached DKIM record from the local store.

#### 2.9 Audit Trail
- **`GET /api/v1/audit`**: Query NIST SP 800-92 compliant audit logs with optional `?action=` filter.

