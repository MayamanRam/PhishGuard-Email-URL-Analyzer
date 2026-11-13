# Product Requirements Document (PRD) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Executive Summary

PhishGuard is an enterprise-grade, defensive cybersecurity platform engineered to empower Security Operations Center (SOC) analysts, incident responders, and digital forensics specialists to rigorously analyze suspicious emails, MIME components, email routing headers, and URL strings in a strictly air-gapped, isolated environment. 

Unlike traditional email gateways or threat intelligence platforms that trigger external DNS queries or make live HTTP connections to adversarial infrastructure, PhishGuard performs 100% offline, deterministic inspection. This guarantees that malicious payloads are never executed, recipient privacy is preserved, and adversaries are never alerted that their campaigns are under active investigation.

---

### 2. Problem Statement & Operational Context

1. **Adversary Reconnaissance via Active Probing:** Conventional threat analysis often involves clicking links, querying live WHOIS records, or resolving DNS records. Adversaries monitor DNS query logs and web server access logs with unique canary tokens to detect SOC scrutiny and burn active infrastructure before forensic attribution is established.
2. **Execution Risk in Manual Triage:** Analysts attempting to inspect suspicious `.eml` or `.msg` files locally risk accidental attachment execution, malicious macro invocation, or browser exploits triggered by embedded JavaScript or remote tracking pixels.
3. **Black-Box Threat Scoring:** Commercial anti-phishing engines produce arbitrary scores (e.g., "78/100") without revealing the underlying mathematical weighting or distinguishing between a single weak heuristic (such as an unusual TLD) and corroborated multi-vector compromise signals.
4. **Unverified Authentication Assumptions:** Novice analysts frequently misinterpret `Authentication-Results:` headers inserted by upstream relays or forged in transit, treating them as cryptographic proof rather than unverified header claims.

---

### 3. User Personas

| Persona | Role | Core Objectives & Pain Points |
| :--- | :--- | :--- |
| **SOC Analyst (Tier 1/2)** | Triage user-reported phishing alerts | Rapidly ingest raw `.eml` files or pasted headers, inspect hop routing for abnormal transit delays, and classify threat severity with full explainability. |
| **Incident Responder (DFIR)** | Deep forensic investigation & containment | Trace originating relay IP addresses, extract and hash attachments without execution, correlate indicators across incidents, and log immutable audit trails. |
| **Security Engineer** | Threat modeling & defensive rule tuning | Review deterministic heuristic rules mapped to MITRE ATT&CK techniques, calibrate category caps to eliminate false positives on legitimate marketing emails. |

---

### 4. Functional Requirements

#### FR-1: Safe Ingestion Pipeline
- The system must accept email inputs via direct `.eml` file upload (up to 10 MB streamed) or raw text paste.
- The ingestion pipeline must compute and log SHA-256 and MD5 cryptographic hashes upon ingestion.
- The raw artifact must be stored in an immutable, read-only evidence vault with restricted filesystem permissions.

#### FR-2: MIME & Content Defanging
- The system must strip all active scripts (`<script>`), objects, and inline frames (`<iframe>`) using a defensive lxml/BeautifulSoup sanitizer.
- Remote tracking images (`<img>`) and external stylesheets must be blocked from automatic loading.
- Hyperlinks must be defanged (`hxxp://`, `hxxps://`, `[.]`) to prevent accidental execution.

#### FR-3: Chronological Hop Routing Forensics
- The system must extract all RFC 5322 `Received:` headers and order them chronologically from originating client relay to final internal MTA.
- The system must calculate transit delays between consecutive hops and flag negative clock skews (>10s) and abnormal latency (>300s).
- The system must extract relay IP addresses, identify RFC 1918 private addresses, and highlight public IPs.

#### FR-4: Sender Identity & Impersonation Detection
- The system must compare `From:` address, `Reply-To:` address, and `Return-Path:` address to detect cross-domain alignment mismatches.
- The system must detect Display Name spoofing where an email address is embedded in the friendly name (e.g., `"security@bank.com" <scammer@evil.ru>`).
- The system must cross-reference display names and sender domains against a protected high-value target brand catalog (e.g., PayPal, Microsoft, Apple, Google).

#### FR-5: Unverified Authentication Claim Auditing
- The system must parse `Authentication-Results:` and `Received-SPF:` headers for SPF, DKIM, and DMARC claims.
- The interface and exported reports must explicitly label all such claims with the mandatory banner: `Unverified Header Claim — Preserved for Forensic Context Only`.

#### FR-6: Static URL Inspection Engine
- The engine must parse URL strings using strict RFC 3986 normalization without DNS or HTTP resolution.
- The engine must parse domain names using an air-gapped, offline Public Suffix List (PSL).
- The engine must detect Punycode (`xn--`), mixed-script Cyrillic/Greek homoglyphs, and calculate Shannon entropy for subdomain randomness.
- The engine must identify literal IPv4, IPv6, and DWORD/hexadecimal host representations.
- The engine must extract and flag open redirect parameters (`redirect_uri`, `return_to`, `url`, `target`).

#### FR-7: Non-Executing Attachment Forensics
- The system must parse MIME attachment boundaries and record filename, declared MIME type, size in bytes, and SHA-256 hash.
- The system must detect double extensions (e.g., `invoice.pdf.exe`), high-risk executable extensions, disk images (`.iso`, `.img`, `.vhd`), and macro-enabled documents (`.docm`, `.xlsm`).
- Attachments must never be written to an executable path or executed in any system process.

#### FR-8: Explainable Category-Grouped Risk Scoring
- The risk scoring engine must categorize indicators into 6 distinct threat domains: Header Routing, Sender Spoofing, Auth Claims, URL Threats, Attachment Risk, and Content Evasion.
- Category contributions must be calculated using an asymptotic diminishing returns formula bounded by explicit mathematical caps.
- The final score must strictly remain within $[0, 100]$.
- A score in the Critical range ($>85$) must require corroborated evidence across at least two threat categories or multiple high-severity findings.

#### FR-9: Incident Case Management
- Analysts must be able to initialize investigation cases, assign severities, track status (`open`, `in_review`, `escalated`, `resolved`, `closed`), and record chronological notes.
- Evidence artifacts (analysis runs, attachments, URLs) must be linkable to one or more investigation cases.

#### FR-10: Forensic Export Engine
- The platform must generate defensible PDF reports using ReportLab with defanged links and zero active annotations.
- The platform must export CSV summaries protected against CSV spreadsheet formula injection (`=`, `+`, `-`, `@`, `\t`, `\r` escaped).
- The platform must export machine-readable JSON payloads containing full structured telemetry and MITRE ATT&CK mappings.

#### FR-11: Append-Only Audit Logging
- Every analysis execution, case state modification, note insertion, and report generation must be recorded in an append-only audit log conforming to NIST SP 800-92 guidelines.

---

### 5. Non-Functional Requirements

- **NFR-1: Air-Gapped Network Isolation:** Automated unit and integration tests must strictly intercept and reject any outbound socket or HTTP connection attempted during analysis.
- **NFR-2: Performance & Latency:** Ingestion and static analysis of a standard email (up to 5 MB with 10 URLs and 3 attachments) must complete in under 500 milliseconds.
- **NFR-3: Memory Safety:** The backend streaming upload filter must reject payloads exceeding 10 MB without buffering the entire payload in memory.
- **NFR-4: Accessibility:** The web console must target WCAG 2.2 AA accessibility standards with high-contrast text, visible focus indicators, and semantic HTML.
- **NFR-5: Cross-Platform Compatibility:** The codebase must execute deterministically on Linux, macOS, and Windows without OS-specific path assumptions.

