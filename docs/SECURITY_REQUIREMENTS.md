# Security Requirements & Compliance Matrix (SECURITY_REQUIREMENTS.md)
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Framework Alignment & Standards Baseline

PhishGuard is engineered according to the defensive cybersecurity baselines defined in:
- **OWASP Application Security Verification Standard (ASVS) v4.0.3 Level 2**
- **OWASP Top 10 (2021)**
- **NIST Cybersecurity Framework (CSF) 2.0** (ID, PR, DE, RS)
- **NIST SP 800-92** (Guide to Computer Security Log Management)

---

### 2. Core Security Controls Specification

#### SEC-01: Air-Gapped Network Isolation (ASVS V1.14 / V12.1)
- **Requirement:** Under no circumstances shall the platform initiate outbound network requests (DNS queries, TCP handshakes, HTTP GET/POST, WHOIS lookups) to analyze target emails or URLs.
- **Threat Mitigated:** Adversary canary alerting, reconnaissance leakage, and command-and-control beaconing.
- **Implementation:**
  - Automated tests configure `unittest.mock` to intercept `socket.create_connection`, `urllib.request.urlopen`, and `http.client.HTTPConnection.connect`, raising `RuntimeError("Network access forbidden in offline analysis mode")` upon invocation.
  - `tldextract` is initialized with `suffix_list_urls=()` and bound to bundled local Public Suffix List files, preventing automatic background fetches.

#### SEC-02: Unverified Header Claim Auditing (ASVS V5.1 / V14.2)
- **Requirement:** SPF, DKIM, and DMARC results found in email headers must be handled as untrusted, unverified forensic claims.
- **Threat Mitigated:** False sense of security caused by attacker-forged `Authentication-Results:` headers inserted upstream or in self-hosted relay hops.
- **Implementation:**
  - `EmailAuthenticationAuditor` explicitly tags all parsed claims with `"verdict": "unverified"`.
  - The UI and ReportLab PDF exporters mandate the prominent disclaimer: `"Unverified Header Claim — Preserved for Forensic Context Only"`.

#### SEC-03: MIME Sanitization & Active Content Stripping (ASVS V5.2 / V5.3)
- **Requirement:** Ingested email bodies must never execute active content, load remote assets, or trigger DOM-based exploits.
- **Threat Mitigated:** Zero-day browser vulnerabilities, remote tracking pixels, cross-site scripting (XSS), and malicious iframes.
- **Implementation:**
  - `DefensiveEmailParser` employs BeautifulSoup with `lxml` parser to recursively strip `<script>`, `<iframe>`, `<object>`, `<embed>`, `<meta>`, and `<form>` tags.
  - All event handler attributes (`onload`, `onerror`, `onclick`) are scrubbed from HTML tokens.
  - Links are defanged into inert text tokens (`hxxp://`, `hxxps://`, `[.]`).

#### SEC-04: Non-Executing Attachment Handling (ASVS V12.1 / V12.5)
- **Requirement:** Attachments must never be stored in an executable path, executed in sub-processes, or dynamically linked.
- **Threat Mitigated:** Accidental malware detonation during SOC analyst triage.
- **Implementation:**
  - `AttachmentForensicsAnalyzer` evaluates binary streams exclusively in-memory to calculate SHA-256 and MD5 fingerprints.
  - Files are inspected against double extensions (`.pdf.exe`, `.docx.vbs`), disk image formats (`.iso`, `.img`, `.vhd`), and macro-enabled documents (`.docm`, `.xlsm`).
  - Raw binary payloads are not written to web-accessible directories.

#### SEC-05: CSV Spreadsheet Formula Injection Defense (ASVS V5.1)
- **Requirement:** Exported CSV reports must neutralize formula injection attacks (CSV Injection / Formula Injection).
- **Threat Mitigated:** Arbitrary code execution or data exfiltration via DDE / formula commands when analysts open reports in Microsoft Excel or LibreOffice Calc.
- **Implementation:**
  - `CsvReportExporter` prepends a single quote (`'`) to any cell value beginning with `=`, `+`, `-`, `@`, `\t`, or `\r`.

#### SEC-06: Path Traversal & Evidence Vault Protection (ASVS V5.5)
- **Requirement:** Storage and retrieval of raw `.eml` evidence or generated PDF/CSV reports must prevent directory traversal attacks.
- **Threat Mitigated:** Arbitrary file read / write outside the application root directory.
- **Implementation:**
  - Storage paths are generated using UUIDv4 filenames and strictly resolved against `PROJECT_ROOT`.
  - `ReportGeneratorService.get_report_file` enforces `os.path.commonpath([target, safe_dir]) == safe_dir` to block `../` escape attempts.

#### SEC-07: Streaming Upload Memory Bounds (ASVS V13.1)
- **Requirement:** The API must reject oversized payloads ($> 10$ MB) before exhausting server memory.
- **Threat Mitigated:** Denial of Service (DoS) via multi-gigabyte upload streams.
- **Implementation:**
  - `StreamingUploadLimitMiddleware` checks the `Content-Length` header for fast rejection, and wraps the ASGI stream with a byte accumulator to terminate un-signaled chunked uploads immediately upon crossing 10 MB.

#### SEC-08: Append-Only Forensics Audit Trail (NIST SP 800-92)
- **Requirement:** All investigative actions, analysis executions, case modifications, and exports must be logged in an append-only audit trail.
- **Threat Mitigated:** Repudiation, insider tampering, and loss of evidence chain of custody.
- **Implementation:**
  - `AuditService` inserts structured events (`AuditEvent`) recording client IP, action type, object UUID, status, and JSON metadata.
  - No update or delete operations are exposed on audit tables.

