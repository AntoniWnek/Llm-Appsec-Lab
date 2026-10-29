# Enterprise HR Copilot — LLM Application Security Lab

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Security Standard](https://img.shields.io/badge/OWASP_LLM_Top_10-2025-critical)
![Architecture](https://img.shields.io/badge/LLM_Engine-Ollama_%7C_Gemini_API-success)
![Tests](https://img.shields.io/badge/Pytest-10_Passing-brightgreen)

An empirical Application Security (AppSec) and AI Red/Blue Teaming laboratory demonstrating how real-world vulnerabilities in tool-using Large Language Model (LLM) agents are exploited and mitigated through deterministic **Defense-in-Depth** engineering.

Instead of relying on fragile prompt-level instructions ("Please do not query restricted tables"), this project proves that securing agentic workflows requires shifting enforcement to **strict schema validation (Pydantic)**, **database driver-level access control (`sqlite3.set_authorizer`)**, **structural input sandboxing**, and **Data Loss Prevention (DLP) output sanitization**.

---

## 1. Architecture & Dual-Mode Design

The application simulates an internal **Enterprise HR Copilot** used by recruiters to search candidate profiles stored in an SQLite database and summarize uploaded PDF/TXT resumes.

The system features a **Provider-Agnostic LLM Engine** (supporting offline execution via **Local Ollama** and cloud execution via **Google Gemini API**) and switches dynamically between two security postures:

### Vulnerable Mode (Flawed Developer Controls)
Simulates realistic enterprise anti-patterns where developers rely on naive perimeter checks and system prompt policies:
- **Raw SQL Tool (`run_raw_sql`):** Allows the LLM to generate arbitrary SQL queries.
- **Bypassable Legacy WAF & SQL Checks:** Blocks casual requests (e.g., `"give me board salaries"`), but contains classic AppSec flaws:
  - **TOCTOU (Time-of-Check to Time-of-Use) Normalization Bug:** Strips zero-width Unicode characters (`U+200B`) and decodes Base64 payloads *after* inspecting the keyword blacklist.
  - **Naive Table Check Bypass:** Verifies whether `"from candidates"` appears in the query string, allowing `UNION SELECT` injections against restricted tables.
  - **Unvalidated Indirect Context (XPIA):** Blindly concatenates raw text streams extracted from uploaded PDF resumes by `pypdf`, including off-canvas text placed at coordinates `(-5000, -5000)` outside the visible page `MediaBox`.
  - **Unvalidated Markdown Rendering:** Allows the LLM to emit external Markdown image tags (`![alt](http://...)`), enabling zero-click client-side data exfiltration.

### Hardened Mode (Defense-in-Depth Architecture)
Replaces probabilistic prompt rules with five deterministic code-level security controls:
1. **Layer 1 — Input Normalization & Heuristic Guardrail (`src/guardrails.py`):** Strips zero-width/control Unicode characters *before* inspection and blocks known injection patterns, encoded SQL prefixes, and unauthorized table references in `< 0.5 ms`.
2. **Layer 2 — Untrusted Document Sandboxing (`src/guardrails.py`):** Strips fake delimiter breakouts from uploaded CVs and isolates resume content inside `<untrusted_cv_data>` XML tags with strict non-execution routing.
3. **Layer 3 — Least-Privilege Tooling & Pydantic Validation (`src/tools.py`):** Removes `run_raw_sql` completely. The model can only invoke `search_candidates_safe`, which validates typed parameters via `CandidateSearchParams` (Pydantic) and executes hardcoded parameterized SQL (`?` placeholders).
4. **Layer 4 — Database Engine-Level Authorizer (`src/tools.py`):** Registers a C-driver callback via `conn.set_authorizer(_hr_sqlite_authorizer)` that returns `sqlite3.SQLITE_DENY` on any attempt to read `board_salaries` or execute non-`SELECT` statements (`DELETE`, `UPDATE`, `DROP`, `PRAGMA`).
5. **Layer 5 — Output DLP & Markdown Sanitizer (`src/guardrails.py`):** Scans model responses for the restricted Canary Honeytoken (`CONF-HR-9921-X`) and executive records, and neutralizes external Markdown image beacons prior to UI rendering.

---

## 2. Threat Coverage — OWASP Top 10 for LLM Applications (2025)

| Test ID | Threat Actor | Attack Scenario | OWASP LLM (2025) Mapping | Vulnerable Mode | Hardened Mode | Primary Mitigating Control |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ATK-01` | Insider (HR User) | System Prompt & Schema Reconnaissance | `LLM07:2025 System Prompt Leakage` | Exploited | Mitigated | Prompt Data Minimization & Input Guardrail |
| `ATK-02` | Insider (HR User) | Direct Prompt Injection (Audit Tag Spoofing) | `LLM01:2025 Prompt Injection` | Exploited | Mitigated | Input Guardrail & Removal of Raw SQL Tool |
| `ATK-03` | Insider (HR User) | Post-WAF Base64 SQL Payload Bypass | `LLM01:2025 Prompt Injection` | Exploited | Mitigated | Pre-Inspection Normalization & Pydantic |
| `ATK-04` | Insider (HR User) | TOCTOU Unicode Zero-Width Smuggling (`U+200B`) | `LLM01:2025 Prompt Injection` | Exploited | Mitigated | Unicode Control Character Stripping |
| `ATK-05` | Insider (HR User) | LLM-Driven `UNION SELECT` SQL Injection | `LLM05:2025 Improper Output Handling` / `LLM06:2025 Excessive Agency` | Exploited | Mitigated | Parameterized Queries & `sqlite3.set_authorizer` |
| `ATK-06` | External Applicant | Off-Canvas PDF Indirect Injection & Zero-Click Exfiltration | `LLM01:2025` / `LLM02:2025 Sensitive Information Disclosure` | Exploited | Mitigated | XML Document Sandbox, Output DLP & Markdown Sanitizer |

---

## 3. Repository Structure

```text
Llm-Appsec-Lab/
├── .github/workflows
│   └── ci.yml                     # Automated Pytest CI pipeline in GitHub Actions
├── data/
│   ├── benchmark_results.json     # Empirical evaluation output across Vulnerable & Hardened modes
│   ├── poisoned_cv.pdf            # Stealth PDF with off-canvas (-5000, -5000) exploit payload
│   ├── poisoned_cv.txt            # Plaintext reference of the poisoned CV payload
│   └── test_cases.json            # Adversarial (ATK-01..06) & Benign (BEN-01..03) test suite
├── docs/
│   └── Threat_Model.md            # Full threat model, trust boundaries, and control analysis
├── reports/
│   ├── Walkthrough.md             # Step-by-step exploitation and verification guide
│   └── benchmark_summary.md       # Auto-generated Markdown benchmark matrix
├── src/
│   ├── __init__.py                # Package marker
│   ├── agent.py                   # Provider-agnostic agent orchestrator (Ollama & Gemini API)
│   ├── app.py                     # Streamlit UI (HR Copilot Chat + SOC SIEM Dashboard)
│   ├── attacker_listener.py       # Local HTTP listener (127.0.0.1:8888) capturing exfiltrated data
│   ├── generate_cv_pdfs.py        # Raw PDF stream generator for off-canvas exploit fixtures
│   ├── guardrails.py              # Input normalization, XML sandboxing, Output DLP & Markdown sanitizer
│   ├── init_db.py                 # SQLite database initializer (candidates + board_salaries)
│   ├── run_benchmark.py           # Automated ASR / FPR benchmark evaluation runner
│   ├── telemetry.py               # Structured JSONL SIEM logger with IoC and Canary detection
│   └── tools.py                   # Vulnerable raw SQL vs. Pydantic + SQLite Authorizer tools
├── tests/
│   └── test_security_controls.py  # Deterministic unit test suite (10 security control tests)
├── .dockerignore                  # Files excluded from the Docker build context
├── .env.example                   # Template for Ollama and Gemini API configuration
├── .gitignore                     # Git exclusions (venv, .env, local SQLite DB, runtime JSONL logs)
├── Dockerfile                     # Non-root container image definition
├── README.md                      # Project overview and reproduction guide
├── pytest.ini                     # Pytest rootpath configuration
└── requirements.txt               # Pinned Python dependencies
```

---

## 4. Quickstart & Reproduction

### Prerequisites

- Python 3.11+

- Option A (Recommended — 100% Offline Local Execution): Ollama installed locally (ollama pull qwen2.5:3b).

- Option B (Cloud API Execution): A Google AI Studio API key (GEMINI_API_KEY).

### Installation

```bash
git clone https://github.com/AntoniWnek/Llm-Appsec-Lab
cd llm-appsec-lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Initialize Database & Generate Off-Canvas Exploit PDF

```bash
python src/init_db.py
python src/generate_cv_pdfs.py
```

### Run the Interactive Lab & SOC Dashboard

```bash
# Terminal 1: Start the Streamlit application
streamlit run src/app.py

# Terminal 2 (Optional): Start the attacker HTTP exfiltration listener on port 8888
python src/attacker_listener.py
```

### Run Automated Security Tests & Empirical Benchmark

```bash
# Execute fast deterministic unit tests (< 1 second)
pytest -v

# Execute the full LLM benchmark suite across Vulnerable and Hardened modes
python src/run_benchmark.py
```
