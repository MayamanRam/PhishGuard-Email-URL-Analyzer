# Security Findings & Hardening Log (SECURITY_FINDINGS.md) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Overview of Triaged Security Findings

During the engineering lifecycle of PhishGuard, several critical security findings, potential attack vectors, and architectural edge cases were triaged, tested, and resolved.

---

### 2. Triaged Findings & Remediation Records

#### SEC-FIND-01: Python 3.14 Event Loop Deadlock in TestClient
- **Severity:** Medium (Testing Integrity)
- **Vulnerability:** Standard Starlette `TestClient` deadlocked on Python 3.14 during thread-local async event loop handoffs, causing tests to stall.
- **Remediation:** Replaced synchronous TestClient with asynchronous `httpx.AsyncClient` utilizing `ASGITransport(app=app)`. This maintained complete end-to-end HTTP pipeline coverage (host validation, security headers, custom client headers, and rate limits) without compromising testing fidelity.

#### SEC-FIND-02: Rate Limiter State Pollution Across Test Suites
- **Severity:** Medium (Quality Assurance & Denial of Service)
- **Vulnerability:** A rate-limiting test mutated the global sliding-window limit to 5 requests/minute. Subsequent tests inherited the depleted quota, causing false-positive HTTP 429 Too Many Requests errors in downstream test suites.
- **Remediation:** Wrapped the rate-limiting test in a strict `try...finally` block that resets the sliding window and restores the original threshold. In addition, an autouse fixture in `conftest.py` was introduced to reset the rate limiter state before every test function.

#### SEC-FIND-03: Relative Path Ambiguity in Evidence Storage
- **Severity:** High (Evidence Vault Integrity & Path Traversal)
- **Vulnerability:** `EVIDENCE_DIR=./data/evidence` in `.env` resolved relative to the process invocation working directory (`D:\Projects`) rather than the PhishGuard project root (`D:\Projects\04-PhishGuard-Email-URL-Analyzer`), leading to potential file path confusion.
- **Remediation:** Implemented Pydantic `model_post_init` in `config.py` that strictly resolves `EVIDENCE_DIR` and `REPORTS_DIR` against `PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent`, and ensures automatic creation of parent directories via `os.makedirs(..., exist_ok=True)`.

#### SEC-FIND-04: Legacy MD5 Hash Flagging in AST Audit (Bandit B324)
- **Severity:** Low (Cryptographic Compliance)
- **Vulnerability:** Use of `hashlib.md5(content).hexdigest()` for forensic indicator matching triggered Bandit B324 warnings regarding weak cryptographic algorithms.
- **Remediation:** Added `usedforsecurity=False` to all MD5 hash computations:
  ```python
  hashlib.md5(content, usedforsecurity=False).hexdigest()
  ```
  Primary cryptographic evidence integrity is anchored in SHA-256.

#### SEC-FIND-05: Exception Swallowing in Telemetry JSON Deserialization (Bandit B110)
- **Severity:** Low (Code Quality & Silent Failure)
- **Vulnerability:** Bare `try...except Exception: pass` blocks in API overview and email routes silently swallowed unexpected parsing exceptions.
- **Remediation:** Explicitly narrowed exception blocks to `except (json.JSONDecodeError, TypeError):` with safe, explicit fallback assignments.

#### SEC-FIND-06: CSV Formula Injection (DDE Command Execution)
- **Severity:** High (Client Exploitation via Export)
- **Vulnerability:** Malicious email subjects or sender display names beginning with `=`, `+`, `-`, `@`, `\t`, or `\r` could trigger Dynamic Data Exchange (DDE) command execution when exported reports were opened in spreadsheet applications.
- **Remediation:** Implemented defensive cell sanitization in `CsvReportExporter`, automatically prepending a single quote (`'`) to neutralise formula interpretation.

#### SEC-FIND-07: Unverified Upstream Authentication Header Spoofing
- **Severity:** High (Analyst Deception / Phishing Bypass)
- **Vulnerability:** Attackers frequently forge `Authentication-Results: spf=pass dkim=pass` in upstream headers to trick analysts into classifying emails as authentic.
- **Remediation:** Programmatically segregated parsed authentication claims into an untrusted forensic tier, displaying a mandatory warning in all UI components and exported PDF reports: `"Unverified Header Claim — Preserved for Forensic Context Only"`.

---

### 3. Residual Security Posture Summary

All triaged findings have been remediated, verified with automated regression tests, and audited with Bandit. The system maintains a zero-defect security posture across all evaluated threat vectors.

