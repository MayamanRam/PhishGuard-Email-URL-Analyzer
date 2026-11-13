# Changelog (CHANGELOG.md) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-11-13
### Added
- **Pure-Python Local YARA Engine:** Offline, in-memory defensive signature scanner (`LocalYaraScanner`) detecting embedded PEs (`SUSPICIOUS_EMBEDDED_PE`), obfuscated PowerShell cradles (`OBFUSCATED_POWERSHELL_CRADLE`), VBA auto-execution macros (`VBA_MACRO_EXECUTION_CHAIN`), HTML smuggling payloads (`HTML_SMUGGLING_PAYLOAD`), and active script downloader objects (`SCRIPT_DOWNLOADER_OBJECTS`) without external C dependencies or binary execution risks. Integrated via rule `ATT-06` with full MITRE ATT&CK mapping (`T1027`, `T1059.001`, `T1204.002`, `T1027.006`, `T1105`).
- **OASIS STIX 2.1 Threat Intelligence Bundle Exporter:** Generates standardized STIX 2.1 JSON threat bundles (`application/stix+json;version=2.1`) containing `identity`, `indicator` (malicious URLs, email senders, attachment SHA-256 hashes), `attack-pattern` (MITRE ATT&CK techniques), and `relationship` (`indicates`) objects for direct SIEM/SOAR ingestion.
- **Air-Gapped DKIM DNS Cache Snapshot & Offline Cryptographic Verification:** RFC 6376 compliant offline cryptographic verification engine (`OfflineDkimVerifier`) verifying RSA-SHA256 and RSA-SHA1 signatures against imported local DNS TXT zone snapshots stored in SQLite (`dkim_dns_records`), strictly preserving zero-network air-gap boundaries.
- **DKIM DNS Cache REST API & Management UI:** Endpoints (`POST /api/v1/dkim-cache/import`, `GET /api/v1/dkim-cache`, `DELETE /api/v1/dkim-cache/{id}`) and interactive modal (`DkimCacheModal`) in the web console for managing offline key snapshots.
- **Automated Verification:** 17 additional unit/integration tests bringing the automated backend test suite to 63 passed tests (100% pass rate) and Bandit AST scan verifying 0 vulnerabilities across 5,292 lines of backend code.

---

## [1.0.0] - 2026-11-13
### Added
- **Full SOC Modern Web Console:** 7 production tabs in React 18 / TypeScript (`DashboardPage`, `EmailAnalyzerPage`, `UrlAnalyzerPage`, `CasesPage`, `FindingsPage`, `ReportsPage`, `AuditPage`).
- **Defensive Email Parser:** RFC 5322 MIME extraction, BeautifulSoup lxml DOM sanitizer, active script stripping, and link defanging (`hxxp://`, `hxxps://`, `[.]`).
- **Email Routing Hop Reconstruction:** Chronological sequence ordering, negative clock skew detection ($< -10$s), transit delay metrics, and RFC 1918 private vs public IP classification.
- **Authentication Claim Auditing:** Parsing of SPF, DKIM, and DMARC claims with mandatory `"Unverified Header Claim"` labeling.
- **Static URL Threat Engine:** RFC 3986 normalization, offline Public Suffix List parsing, Punycode decoding (`xn--`), mixed-script Cyrillic homoglyph detection, Shannon entropy calculations, and open redirect parameter extraction.
- **Attachment Forensics:** In-memory metadata inspection, double extension detection (`.pdf.exe`), disk image formats (`.iso`), macro-enabled documents (`.docm`), and SHA-256 fingerprinting without binary execution.
- **Explainable Mathematical Scoring:** Asymptotic diminishing returns category model ($S_c = \text{Cap}_c \times [1 - \prod(1 - \frac{W_r \times \text{Conf}_r}{\text{Cap}_c + 15})]$) with Multi-Vector Corroboration Guardrail.
- **Deterministic Rule Catalog:** 27 heuristic rules seeded in SQLite with direct MITRE ATT&CK mappings.
- **Incident Case Management:** Case creation, status updates (`open`, `in_review`, `resolved`, `closed`), chronological analyst notes, and artifact correlation.
- **Defensive Report Exporter:** ReportLab PDF generator with defanged text and zero active links, formula-escaped CSV exporter, and structured JSON telemetry.
- **Append-Only Audit Trail:** Chronological event logging conforming to NIST SP 800-92.
- **Comprehensive Test Suite:** 46 automated backend pytest tests and 5 frontend Vitest tests with 100% pass rate.
- **Security Verification:** AST static analysis via Bandit reporting 0 issues across 4,302 lines of code.

---

## [0.2.0] - 2026-11-12
### Added
- Project scaffolding for FastAPI backend and Vite/React/TypeScript frontend.
- SQLite WAL configuration with strict foreign key pragmas.
- Alembic database migration environment and declarative SQLAlchemy models for 12 tables.
- Security middleware pipeline: `StreamingUploadLimitMiddleware` (10 MB bound), custom client header CSRF protection (`X-PhishGuard-Client`), `TrustedHostMiddleware`, and sliding-window rate limiting.
- Air-gapped offline socket interception tests.

---

## [0.1.0] - 2026-11-11
### Added
- Initial architectural design, mathematical risk scoring formalization, PRD, and TRD.
- STRIDE threat model and security engineering specifications.

