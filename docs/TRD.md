# Technical Requirements Document (TRD) — PhishGuard
## Project 04: Defensive Phishing Email & URL Threat Analysis Platform

---

### 1. Architectural & Technology Stack Specification

| Component | Technology | Version | Purpose & Technical Justification |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | FastAPI / Starlette | >= 0.115.0 | High-performance asynchronous REST API with native Pydantic schema validation and ASGI pipeline control. |
| **Data Validation** | Pydantic v2 | >= 2.10.0 | Strict type coercion, immutable settings models, and JSON schema generation. |
| **Persistence / ORM** | SQLAlchemy 2.0 | >= 2.0.36 | Typed declarative ORM supporting modern 2.0 select syntax, relationship cascade controls, and transaction isolation. |
| **Schema Migrations** | Alembic | >= 1.14.0 | Deterministic database schema version control with automated downgrade scripts. |
| **Database Engine** | SQLite 3 | >= 3.40.0 | Lightweight, serverless local relational engine operating in Write-Ahead Logging (WAL) mode with strict foreign keys. |
| **HTML Sanitizer** | BeautifulSoup4 / lxml | >= 4.12.0 | Robust XML/HTML DOM parsing and tree-walking to strip malicious script tags, iframes, and remote payloads. |
| **Domain Analysis** | tldextract | >= 5.1.0 | RFC-compliant Public Suffix List parsing configured strictly in offline mode (`suffix_list_urls=()`). |
| **Report Generation** | ReportLab | >= 4.2.0 | Low-level programmatic PDF rendering with plain-text canvas layout and zero active hyperlink annotations. |
| **Frontend Framework**| React | >= 18.3.0 | Modern declarative UI with component modularity and efficient virtual DOM diffing. |
| **Language / Compiler**| TypeScript | >= 5.6.0 | Strict compile-time type checking with zero implicit `any` and full coverage of API schemas. |
| **Build Tooling** | Vite | >= 6.0.0 | Fast HMR development server and optimized Rollup production bundler. |
| **Styling** | Tailwind CSS | >= 3.4.0 | Utility-first, responsive design system with a specialized tactical cybersecurity palette. |

---

### 2. Core Forensic & Parsing Algorithms

#### 2.1 RFC 5322 MIME Structure Parsing
- **Parser Core:** Utilizes Python's native `email.parser.BytesParser` with `policy=email.policy.default`.
- **Payload Extraction:** Traverses MIME multipart trees via `iter_parts()`. Content types are categorized into:
  - `text/plain`: Preserved in raw text after UTF-8 replacement decoding.
  - `text/html`: Passed through the Defensive Sanitizer.
  - Attachments (`Content-Disposition: attachment` or named parts): Metadata parsed and payload hashed with SHA-256; binary payload is dropped from memory immediately after hashing unless raw preservation is enabled.

#### 2.2 Defensive HTML Sanitization
```python
# Conceptual AST Sanitization Flow
def sanitize_html(raw_html: str) -> str:
    soup = BeautifulSoup(raw_html, "lxml")
    for tag in soup(["script", "iframe", "embed", "object", "form", "meta", "base"]):
        tag.decompose()
    for el in soup.find_all(True):
        for attr in list(el.attrs):
            if attr.startswith("on") or attr in ["src", "action", "data"]:
                del el.attrs[attr]
            if attr == "href":
                el["href"] = defang_link(el["href"])
    return str(soup)
```

#### 2.3 Chronological Routing Hop Reconstruction
1. Collect all `Received:` header clauses in sequence.
2. Reverse the list so that index 0 corresponds to the originating sender MTA.
3. For each hop:
   - Extract `from`, `by`, `with`, and `id` tokens via regular expressions.
   - Extract IP addresses using regex `r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'`.
   - Classify IP address against RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).
   - Parse timestamp using `email.utils.parsedate_to_datetime`.
   - Calculate $\Delta t = t_i - t_{i-1}$. If $\Delta t < -10$, record a Negative Clock Skew anomaly. If $\Delta t > 300$, record an Abnormal Latency anomaly.

#### 2.4 Shannon Entropy Calculation
Domain and URL randomness is evaluated using the standard Shannon Entropy formula:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Where $P(x_i)$ is the frequency of character $x_i$ within the evaluated string.
- Strings with length $>12$ and $H(X) > 4.5$ are flagged as algorithmically generated or high-randomness domains.

---

### 3. Memory & Resource Management

- **Streaming Upload Guardrail:** The custom Starlette middleware `StreamingUploadLimitMiddleware` intercepts requests to `/api/v1/emails/analyze`.
  - Step 1: Check `Content-Length`. If header exceeds $10 \times 1024 \times 1024$ bytes (10 MB), request is immediately rejected with HTTP 413 without reading the body.
  - Step 2: For chunked or streaming uploads where `Content-Length` is missing or spoofed, the middleware wraps the ASGI receive callable and tracks cumulative received bytes. If byte count exceeds 10 MB, a 413 Payload Too Large response is returned and downstream processing halts immediately.
- **Result Set Paging:** All database queries for cases, findings, and audit logs enforce a maximum page size of 100 records with indexed cursor offset pagination to prevent heap exhaustion.

---

### 4. Database Concurrency & Reliability

SQLite is configured via SQLAlchemy connection execution listeners with the following performance and integrity pragmas:
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 30000;
```
- **WAL Mode:** Permits simultaneous concurrent readers without blocking write transactions.
- **Foreign Keys:** Enforces referential integrity cascades (`ON DELETE CASCADE` for findings and associations).
- **Busy Timeout:** Configured to 30,000 milliseconds to prevent lock contention errors under concurrent API requests.

