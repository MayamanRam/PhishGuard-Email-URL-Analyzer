# Risk Register (RISK_REGISTER.md) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Risk Assessment Methodology

Risks are quantified using standard NIST SP 800-30 qualitative impact and likelihood scales:
- **Likelihood:** 1 (Rare) to 5 (Almost Certain)
- **Impact:** 1 (Insignificant) to 5 (Catastrophic)
- **Risk Score:** $\text{Likelihood} \times \text{Impact}$ (1–25 scale)
  - **1–6:** Low | **8–12:** Medium | **15–25:** High/Critical

---

### 2. Comprehensive Risk Register

| Risk ID | Risk Description | Initial L | Initial I | Initial Score | Implemented Defensive Control | Residual L | Residual I | Residual Score | Risk Status |
| :--- | :--- | :---: | :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| **RSK-01** | **Accidental Detonation:** Analyst accidentally executes an attachment during triage. | 4 | 5 | **20 (High)** | In-memory SHA-256 fingerprinting; binary attachments are never written to executable paths or executed. | 1 | 5 | **5 (Low)** | Controlled |
| **RSK-02** | **Adversary Alerting:** PhishGuard queries external DNS or HTTP endpoints, burning investigation. | 4 | 4 | **16 (High)** | Air-gapped isolation with socket blocking; tldextract bound to offline local caches with `suffix_list_urls=()`. | 1 | 4 | **4 (Low)** | Controlled |
| **RSK-03** | **False-Positive Noise:** Legitimate marketing newsletters classified as Critical phishing. | 4 | 3 | **12 (Med)** | Diminishing returns category caps; multi-vector corroboration requirement before score can exceed 85. | 2 | 2 | **4 (Low)** | Controlled |
| **RSK-04** | **Unverified Auth Trust:** Upstream forged `Authentication-Results:` headers accepted as authentic. | 4 | 4 | **16 (High)** | Claims are audited without implicit trust; mandatory UI and PDF warning banner on all SPF/DKIM/DMARC results. | 1 | 4 | **4 (Low)** | Controlled |
| **RSK-05** | **Heap Exhaustion / DoS:** Adversary submits massive multi-gigabyte upload or chunked stream. | 3 | 4 | **12 (Med)** | Streaming ASGI middleware rejecting payloads $>10$ MB via Content-Length and real-time received byte counter. | 1 | 3 | **3 (Low)** | Controlled |
| **RSK-06** | **CSV Formula Injection:** Analyst opens exported CSV report in Excel, triggering arbitrary command execution via DDE. | 3 | 4 | **12 (Med)** | `CsvReportExporter` prepends a single quote (`'`) to any cell beginning with `=`, `+`, `-`, `@`, `\t`, or `\r`. | 1 | 4 | **4 (Low)** | Controlled |
| **RSK-07** | **Path Traversal:** Attacker requests report with `../../` sequence to read host files. | 2 | 4 | **8 (Med)** | `os.path.commonpath` verification ensuring report retrieval cannot escape `data/reports/`. | 1 | 4 | **4 (Low)** | Controlled |
| **RSK-08** | **SQLite Lock Contention:** Multiple concurrent API requests trigger database lock errors. | 3 | 3 | **9 (Med)** | SQLite WAL mode enabled with `PRAGMA synchronous = NORMAL;` and 30-second busy timeout. | 1 | 2 | **2 (Low)** | Controlled |

---

### 3. Monitoring & Review Schedule

The Risk Register is reviewed bi-weekly by the lead security engineer. Any modification to detection rules, parser logic, or third-party dependencies triggers an immediate re-evaluation of residual risk scores.

