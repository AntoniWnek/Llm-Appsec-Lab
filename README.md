# Enterprise HR Copilot — LLM Application Security Lab

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Security Standard](https://img.shields.io/badge/OWASP_LLM_Top_10-2025-critical)
![Architecture](https://img.shields.io/badge/LLM_Engine-Ollama_%7C_Gemini_API-success)
![Tests](https://img.shields.io/badge/Pytest-49_Passing_(21_Test_Functions)-brightgreen)
![DevSecOps](https://img.shields.io/badge/CI-Pytest_%7C_Bandit_SAST_%7C_pip--audit-informational)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

An empirical Application Security (AppSec) and AI Red/Blue Teaming laboratory demonstrating how vulnerabilities in tool-using Large Language Model (LLM) agents are exploited and mitigated through deterministic **Defense-in-Depth** engineering.

Rather than treating system prompts or XML delimiters as security boundaries, this project enforces security at **verifiable code and data boundaries**: **task-based zero-tool scoping (`tools=None` during document summarization)**, **strict schema validation (Pydantic)**, **database C-driver access control (`sqlite3.set_authorizer`)**, **database egress sanitization**, **Zero-Trust SSRF egress guards (`ipaddress`)**, **OWASP LLM10:2025 sliding-window rate/token budgets**, **dynamic database-backed Output DLP**, and **tamper-evident SHA-256 SIEM audit logging**.

---

## 1. Architecture & Dual-Mode Design

The application simulates an internal **Enterprise HR Copilot** used by recruiters to search synthetic candidate profiles in SQLite, verify candidate portfolio links, and summarize uploaded PDF/TXT resumes.

### Vulnerable Mode (Flawed Developer Controls)
Simulates realistic enterprise anti-patterns where developers rely on naive perimeter checks and prompt instructions:
- **Overprivileged Agency (`run_raw_sql` & `fetch_portfolio_url`):** Allows the LLM to generate raw SQL queries and fetch unvalidated URLs.
- **Bypassable Legacy WAF & SQL Checks:** Blocks casual requests (e.g., `"show me board salaries"`), but contains realistic implementation flaws:
  - **TOCTOU (Time-of-Check to Time-of-Use) Normalization Bug:** Strips zero-width Unicode characters (`U+200B`) and decodes Base64 payloads *after* inspecting the keyword blacklist (`ATK-03`, `ATK-04`).
  - **Naive Substring Validation:** Checks whether `"from candidates"` appears in the query string, allowing `UNION SELECT` injections against `board_salaries` (`ATK-05`).
  - **Off-Canvas PDF Parser Differential (`ATK-06`):** Concatenates raw text streams extracted by `pypdf`, including hidden instructions placed at coordinates `(-5000, -5000)` outside the PDF `MediaBox [0 0 612 792]`.
  - **Implicit Trust in Internal Database Rows (`ATK-07`):** Executes dormant Second-Order Stored Prompt Injections retrieved from candidate skill columns (`Victor Reznov`).
  - **Simulated Cloud IMDSv1 SSRF (`ATK-08`):** Accepts metadata-like URLs (e.g., `169.254.169.254`) and redirects demonstration requests locally to the mock listener at `127.0.0.1:8888` (or returns an in-memory synthetic AWS STS-style payload containing `ASIA-HR-PROD-9921` if the listener is unavailable).

### Hardened Mode (Tool & Data Boundary Enforcement)
In `Hardened` mode, superficial chat keyword filters are removed so that adversarial inputs are tested against deterministic backend boundaries:
1. **Layer 1a & 1b — Unicode Normalization & OWASP LLM10 Consumption Guard (`src/guardrails.py`):** Strips zero-width control characters (`U+200B`–`U+200F`, `U+FEFF`), caps input length (`MAX_PROMPT_CHARS = 4000`), and enforces a sliding-window rate limiter (`15` req/min -> `BLOCKED_RATE_LIMIT_EXCEEDED`) and token budget ceiling (`BLOCKED_TOKEN_BUDGET_EXCEEDED`).
2. **Layer 2 — Task-Based Zero-Tool Scoping & XML Structuring (`src/agent.py`, `src/guardrails.py`):** Because `<untrusted_cv_data>` XML tags are structural delimiters rather than a hard security boundary, the orchestrator enforces **Zero-Tool Scoping** whenever `cv_attached=True` by passing `active_tools = []` (`tools=None`) to the model, physically detaching all database and network tools during resume summarization.
3. **Layer 3a — Tool Registry Isolation & Pydantic Parameterized SQL (`src/tools.py`):** Detaches `run_raw_sql` (`BLOCKED_UNAUTHORIZED_TOOL`). Exposes only `search_candidates_safe`, which validates parameters via `CandidateSearchParams` (Pydantic) and executes hardcoded parameterized SQL (`?` placeholders).
4. **Layer 3b — Database Egress Sanitizer (`src/guardrails.py`):** Applies Zero-Trust sanitization (`sanitize_db_record_value`) to SQLite rows before they enter the LLM context, neutralizing Second-Order Stored Injections (`BLOCKED_STORED_DB_INJECTION`).
5. **Layer 3c — Zero-Trust SSRF Egress Guard (`src/guardrails.py`):** Validates URLs via `urllib.parse` and `ipaddress.ip_address()`, enforcing `https://`, blocking loopback/private/link-local (`169.254.0.0/16`) addresses, and restricting outbound requests to an explicit domain allowlist (`github.com`, `gitlab.com`, `linkedin.com`).
6. **Layer 4 — SQLite C-Driver Authorizer (`src/tools.py`):** Registers `conn.set_authorizer(_hr_sqlite_authorizer)` to enforce `sqlite3.SQLITE_DENY` at query compilation time on any access to `board_salaries` or non-read operations (`DELETE`, `UPDATE`, `DROP`, `PRAGMA`).
7. **Layer 5 — Dynamic Database-Backed Output DLP & Media Sanitizer (`src/guardrails.py`):** Dynamically loads protected executive entities from SQLite, blocks responses containing synthetic Canary Honeytokens (`CONF-HR-9921-X`, `CANARY-CLOUD-IAM-KEY-*`), and neutralizes external Markdown/HTML media tags.
8. **Layer 6 — Tamper-Evident SHA-256 SIEM Audit Log (`src/telemetry.py`):** Chains every JSONL security event via SHA-256 (`prev_hash` -> `event_hash`) and verifies log integrity on load in the SOC Dashboard.

---

## 2. Threat Coverage — OWASP Top 10 for LLM Applications (2025)

| Test ID | Threat Domain / Actor | Attack Scenario | OWASP LLM (2025) Mapping | Vulnerable Mode | Hardened Mode | Enforcing Boundary in Hardened Mode |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ATK-01` | Domain 1: Internal Recruiter | System Prompt & Schema Reconnaissance | `LLM07:2025 System Prompt Leakage` | Exploited | Mitigated | Architectural Schema Omission (`HARDENED_SYSTEM_PROMPT`) |
| `ATK-02` | Domain 1: Internal Recruiter | Direct Prompt Injection (Audit Tag Spoofing) | `LLM01:2025 Prompt Injection` | Exploited | Mitigated | Tool Registry Isolation (`BLOCKED_UNAUTHORIZED_TOOL`) |
| `ATK-03` | Domain 1: Internal Recruiter | Post-WAF Base64 SQL Payload Bypass | `LLM01:2025 Prompt Injection` | Exploited | Mitigated | Tool Registry Isolation (`BLOCKED_UNAUTHORIZED_TOOL`) |
| `ATK-04` | Domain 1: Internal Recruiter | TOCTOU Unicode Zero-Width Smuggling (`U+200B`) | `LLM01:2025 Prompt Injection` | Exploited | Mitigated | Pre-Normalization + Tool Registry (`BLOCKED_UNAUTHORIZED_TOOL`) |
| `ATK-05` | Domain 1: Internal Recruiter | LLM-Driven `UNION SELECT` SQL Injection | `LLM05:2025` / `LLM06:2025 Excessive Agency` | Exploited | Mitigated | Tool Registry / Pydantic Validation & SQLite Authorizer |
| `ATK-06` | Domain 2: External Candidate | Off-Canvas PDF Indirect Injection & Exfiltration | `LLM01:2025` / `LLM02:2025` / `LLM05:2025` | Exploited | Mitigated | Zero-Tool Scoping (`tools=None`) & XML Structuring |
| `ATK-07` | Domain 2: External Candidate | Second-Order (Stored) DB Injection (`Victor Reznov`) | `LLM01:2025` / `LLM02:2025 Sensitive Info Disclosure` | Exploited | Mitigated | Database Egress Sanitizer (`BLOCKED_STORED_DB_INJECTION`) |
| `ATK-08` | Domain 1 & 3: Runtime Network | Agentic SSRF to Simulated Cloud IMDS (`169.254.169.254`) | `LLM06:2025 Excessive Agency` / `SSRF` | Exploited | Mitigated | Zero-Trust SSRF Egress Guard (`BLOCKED_SSRF_EGRESS_GUARD`) |
| `LLM10 (Pytest)` | Domain 1 & 3: Runtime Resource | Request Flooding & Token Budget Exhaustion | `LLM10:2025 Unbounded Consumption` | Unbounded | Mitigated | Sliding-Window Rate & Token Limiter (`BLOCKED_RATE_LIMIT_EXCEEDED`) |
---

## 3. Scope of Security Claims & Known Limitations

This project is an isolated security research environment using synthetic data and simulated endpoints:
- **Deterministic vs. Probabilistic Separation & Evaluation Routing:** Because LLM outputs vary across runs and model sizes, `src/run_benchmark.py` separates mitigations enforced deterministically by backend code (`DETERMINISTIC_CODE_CONTROL`) from unblocked turns where the model refused on its own (`PROBABILISTIC_MODEL_BEHAVIOR`). Deterministic Boundary Routing (`_route_hardened_tool_boundaries()`, enabled via `evaluation_mode=True`) is an evaluation-only fallback used to exercise backend security controls when a local model does not emit native structured tool calls; its results verify backend enforcement and are not treated as evidence of model-level attack resistance.
- **Turn-Scoped Tool Omission & XML Delimiters:** `<untrusted_cv_data>` tags are structural markers, not an independent security boundary. When `cv_attached=True` in `Hardened` mode, the orchestrator omits tool definitions from that provider request (`tools=None`) while the backend independently enforces tool authorization.
- **Simulated Cloud Metadata & DNS Rebinding:** `ATK-08` simulates an AWS IMDSv1 endpoint locally (redirecting demonstration metadata requests to `127.0.0.1:8888` or a synthetic `ASIA-...` fallback); no real cloud infrastructure is contacted. Production SSRF defenses must pair application-layer URL/IP validation with single-resolution IP pinning, disabled HTTP redirects, and network-layer VPC egress rules to prevent DNS rebinding.
- **SIEM Integrity vs. External Authenticity & In-Memory Limits:** The `SHA-256` hash chain in `src/telemetry.py` verifies internal chain consistency (*integrity*) against single-record modification or deletion, but full *authenticity* against whole-file hash recomputation by a privileged local attacker requires an external trust anchor (e.g., `HMAC-SHA256` or remote append-only SIEM). Similarly, the `OWASP LLM10` sliding-window limiter uses heuristic token estimation in process memory rather than a distributed state store or BPE tokenizer.

For deep-dive documentation, see:
- [`docs/Threat_Model.md`](docs/Threat_Model.md) — 3-Domain Threat Model, trust boundaries, and residual risk analysis.
- [`docs/Engineering_Log.md`](docs/Engineering_Log.md) — 5-Stage architectural decision log (*Problem -> Decision -> Rationale -> Verification*).
- [`CHANGELOG.md`](CHANGELOG.md) — Milestone history following *Keep a Changelog*.
- [`reports/Walkthrough.md`](reports/Walkthrough.md) — Step-by-step exploitation and defense verification walkthrough.
---

## 4. Repository Structure

```text
Llm-Appsec-Lab/
├── .github/
│   └── workflows/
│       └── ci.yml                 # Automated Pytest (49 cases), Bandit SAST & pip-audit CI pipeline
├── data/
│   ├── benchmark_results.json     # Empirical evaluation output (ATK-01..08 & BEN-01..03)
│   ├── poisoned_cv.pdf            # Stealth PDF with off-canvas (-5000, -5000) exploit payload
│   ├── poisoned_cv.txt            # Plaintext reference of the poisoned CV payload
│   └── test_cases.json            # Adversarial (ATK-01..08) & Benign (BEN-01..03) test suite
├── docs/
│   ├── Engineering_Log.md         # Architectural progression & design rationale (Stages 1-5)
│   └── Threat_Model.md            # 3-Domain threat model, trust boundaries & limitations
├── reports/
│   ├── screenshots/               # Visual verification screenshots for the walkthrough
│   ├── Walkthrough.md             # Step-by-step exploitation and defense verification guide
│   └── benchmark_summary.md       # Auto-generated Markdown benchmark matrix
├── src/
│   ├── __init__.py                # Package marker
│   ├── agent.py                   # Provider-agnostic agent orchestrator (Ollama & Gemini API)
│   ├── app.py                     # Streamlit UI (HR Copilot Chat + SOC SIEM Dashboard)
│   ├── attacker_listener.py       # Local HTTP listener (127.0.0.1:8888) for exfil & mock IMDS
│   ├── generate_cv_pdfs.py        # Raw PDF stream generator for off-canvas exploit fixtures
│   ├── guardrails.py              # Normalization, LLM10 limiter, DB/SSRF guards & dynamic DLP
│   ├── init_db.py                 # SQLite initializer (candidates, stored payload & board_salaries)
│   ├── run_benchmark.py           # Benchmark runner (Deterministic vs. Probabilistic metrics)
│   ├── telemetry.py               # Tamper-evident SHA-256 JSONL SIEM logger & integrity verifier
│   └── tools.py                   # Vulnerable raw tools vs. Pydantic, Authorizer & SSRF-safe tools
├── tests/
│   └── test_security_controls.py  # 49 automated test cases across 21 test functions
├── .dockerignore                  # Files excluded from the Docker build context
├── .env.example                   # Template for Ollama and Gemini API configuration
├── .gitignore                     # Git exclusions (venv, .env, local SQLite DB, runtime JSONL logs)
├── CHANGELOG.md                   # Chronological milestone release summary
├── Dockerfile                     # Non-root container image definition
├── LICENSE                        # MIT License
├── README.md                      # Project overview and reproduction guide
├── pytest.ini                     # Pytest rootpath configuration
└── requirements.txt               # Python dependency specifications
```

---

## 5. Quickstart & Automated Verification

```bash
git clone https://github.com/AntoniWnek/Llm-Appsec-Lab.git
cd Llm-Appsec-Lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# 1. Initialize SQLite database (with dormant ATK-07 row) & generate off-canvas PDF
python src/init_db.py
python src/generate_cv_pdfs.py

# 2. Run all 49 automated security test cases (unit, negative boundary, SHA-256 SIEM, LLM10 DoS & integration)
pytest -v

# 3. Launch the interactive Streamlit Lab & SOC Dashboard
streamlit run src/app.py

# 4. Run the full 11-case empirical benchmark (ATK-01..08 + BEN-01..03)
python src/run_benchmark.py
```
