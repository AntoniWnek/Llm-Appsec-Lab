# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This repository is maintained as a continuously evolving security research lab and does not currently publish formal, version-tagged releases. Therefore, completed changes are documented chronologically under `[Unreleased]`, grouped by engineering milestone.

---

## [Unreleased]

### Milestone 4: Tamper-Evident SIEM Audit Chain, LLM10 DoS Guardrails & DevSecOps SAST/SCA (2026-11)

#### Added
- **Tamper-Evident SHA-256 SIEM Hash Chain (`src/telemetry.py`, `src/app.py`):** Linked every security event in `data/telemetry.jsonl` using cryptographic SHA-256 digests (`prev_hash` and `event_hash` anchored to `GENESIS_HASH`). Added `verify_telemetry_integrity()` and live audit-trail verification alerts in the Streamlit SOC Dashboard to verify internal chain consistency and detect record modification or deletion relative to an uncorrupted initial state.
- **OWASP LLM10:2025 Unbounded Consumption Guardrail (`src/guardrails.py`, `src/agent.py`):** Implemented an in-memory per-process sliding-window rate limiter (`MAX_REQUESTS_PER_WINDOW = 15` per `60s` -> `BLOCKED_RATE_LIMIT_EXCEEDED`) and a **heuristic token-budget estimator** (`estimate_token_count()` using deterministic character and word heuristics for coarse resource-budget enforcement: `MAX_SINGLE_TURN_TOKENS = 1200`, `MAX_TOKENS_PER_WINDOW = 6000` -> `BLOCKED_TOKEN_BUDGET_EXCEEDED`).
- **DevSecOps SAST & SCA Pipeline (`.github/workflows/ci.yml`):** Integrated **Bandit** (Static Application Security Testing on `src/`) and **pip-audit** (Software Composition Analysis on `requirements.txt`) into GitHub Actions CI alongside the automated `pytest` suite.
- Expanded automated test coverage in `tests/test_security_controls.py` to **49 executed test cases across 21 test functions** (comprising unit checks, parametrized negative boundary suites, and mocked-LLM integration tests), including log-tampering checks and sliding-window rate/token exhaustion tests.

---

### Milestone 3: Architectural Boundary Hardening & Deterministic Evaluation (2026-11)

#### Added
- Added `docs/Engineering_Log.md` documenting the project's architectural evolution using the *Problem → Technical Decision → Engineering Rationale → Verification* framework.
- Added an MIT `LICENSE`, including the standard warranty and liability disclaimers.
- Expanded `docs/Threat_Model.md` to cover three distinct threat domains: **Internal Recruiter**, **External Candidate**, and **Execution Environment / Runtime**.
- Introduced benchmark outcome classification in `src/run_benchmark.py`, distinguishing `DETERMINISTIC_CODE_CONTROL` from `PROBABILISTIC_MODEL_BEHAVIOR`.
- Added explicit `evaluation_mode` separation in `src/agent.py` so that `_route_hardened_tool_boundaries()` acts strictly as an evaluation-only fallback (disabled by default during normal execution `evaluation_mode=False`).
- Documented residual security risks and methodological limitations, including model-level semantic misclassification, application-layer versus network-layer SSRF protection (DNS rebinding and multi-lookup socket risks), evaluation-only boundary routing vs. natural model tool calling, in-memory rate-limiting state, and internal hash-chain consistency vs. external log authenticity.

#### Changed
- **Shifted Primary Enforcement to Tool & Data Boundaries:** Removed SQL and table-name keyword blacklists from Layer 1 (`inspect_user_input`). Adversarial prompts now reach downstream security boundaries instead of being trivially rejected at the chat-input layer, exercising tool authorization (`BLOCKED_UNAUTHORIZED_TOOL`), Pydantic validation (`BLOCKED_BY_PYDANTIC`), and SQLite authorization (`BLOCKED_BY_AUTHORIZER`).
- **Implemented Task-Based Zero-Tool Scoping for Document Summarization:** Updated `src/agent.py` so that when an untrusted CV is attached in `Hardened` mode (`cv_attached=True`), the orchestrator omits all tool declarations from the provider request for that LLM turn (`active_tools = []`, passed as `tools=None`), while the backend dispatcher independently enforces tool authorization.
- **Replaced Hardcoded DLP Entities with Dynamic Database Loading:** Refactored `inspect_and_sanitize_output()` in `src/guardrails.py` to dynamically load protected executive names, compensation figures, and markers directly from the `board_salaries` SQLite table (`_load_protected_entities_from_db()`), eliminating hardcoded PII/salary strings in filter code.
- **Generalized Document-Boundary & Media Sanitization:** Replaced hardcoded CV delimiter string splitting with generic boundary pattern matching and expanded `MARKDOWN_IMAGE_RE` to neutralize reference-style Markdown images, `data:`/`file:` URIs, and raw HTML active tags (`<img>`, `<iframe>`, `<script>`, `<object>`, `<embed>`).

#### Fixed
- Corrected optional status-filter handling in `CandidateSearchParams` to normalize generic filler values (`"all"`, `"any"`, `"none"`) emitted by smaller local LLMs before validation and SQL query construction, preventing unintended empty query results.

#### Security
- Expanded negative boundary tests to cover IPv4-mapped IPv6 representations of cloud metadata addresses (`::ffff:169.254.169.254`), SQLite subqueries, unauthorized `PRAGMA` statements, and oversized file uploads.

---

### Milestone 2: Second-Order Stored Injection & Agentic SSRF Boundaries (2026-10)

#### Added
- **Scenario 5 (`ATK-07`) — Second-Order Stored Prompt Injection:** Introduced a synthetic candidate record (`Victor Reznov`) in SQLite (`src/init_db.py`) containing a dormant prompt-injection payload in the `key_skills` field. The record is isolated from benign benchmark cases (`BEN-01`–`BEN-03`).
- **Scenario 6 (`ATK-08`) — Agentic SSRF (Simulated Cloud Metadata Access):** Added the `fetch_portfolio_url` tool (which redirects demonstration metadata requests to the local mock listener on `127.0.0.1:8888` or falls back to a synthetic payload) returning synthetic AWS STS-style credentials (`ASIA-HR-PROD-9921`).
- Added database egress sanitization through `sanitize_db_record_value()` with the security event `BLOCKED_STORED_DB_INJECTION`.
- Added outbound URL validation through `validate_safe_egress_url()` with the security event `BLOCKED_SSRF_EGRESS_GUARD`.

#### Security
- Introduced sanitization of untrusted text fields retrieved from SQLite before including database records in the LLM prompt context.
- Restricted outbound portfolio-verification requests in `Hardened` mode to HTTPS URLs on explicitly allowlisted external domains (`github.com`, `gitlab.com`, and `linkedin.com`).
- Added destination validation to reject loopback, private IPv4/RFC1918, and link-local address ranges, including the cloud metadata range `169.254.0.0/16`.

---

### Milestone 1: Core Dual-Mode Lab, Defense-in-Depth Controls & SIEM Telemetry (2026-10)

#### Added
- Implemented the initial dual-mode Enterprise HR Copilot with intentionally vulnerable (`Vulnerable`) and security-hardened (`Hardened`) configurations using Python, Streamlit, and SQLite.
- Added provider-agnostic LLM orchestration supporting local Ollama (`qwen2.5:3b`), including a fallback JSON tool-call parser for models with limited native tool-calling support, and the Google Gemini API.
- Implemented an intentionally vulnerable database tool (`run_raw_sql`) to demonstrate excessive tool privileges and unsafe SQL execution.
- Added PDF and TXT CV extraction through `extract_cv_text()`, including a 2 MB upload-size limit.
- Implemented offensive scenarios demonstrating Unicode normalization/canonicalization bypasses using zero-width characters (`U+200B`), post-filter Base64 decoding, and substring-based SQL allowlist bypasses using `UNION SELECT`.
- Added an off-canvas PDF exploit generator (`src/generate_cv_pdfs.py`) that places indirect prompt-injection payloads at coordinates `(-5000, -5000)`, outside the PDF `MediaBox`.
- Added a local HTTP listener (`src/attacker_listener.py`) on port `8888` to capture simulated Markdown image-beacon callbacks.
- Implemented hardened backend controls using `CandidateSearchParams` (Pydantic), parameterized SQL queries, and SQLite-level access restrictions through `Connection.set_authorizer()`.
- Added output DLP scanning for synthetic Canary Honeytokens (`CONF-HR-9921-X`).
- Added Markdown image neutralization and untrusted CV content isolation.
- Introduced structured JSONL security telemetry in `src/telemetry.py`, recording execution metadata, tool activity, security events, and detected indicators.
- Added a Pandas-powered Streamlit SOC dashboard for reviewing security telemetry.
- Implemented an automated benchmark runner (`src/run_benchmark.py`) evaluating Attack Success Rate (ASR) on adversarial scenarios and False Positive Rate (FPR) on benign recruiter queries.
- Added a non-root Docker configuration and GitHub Actions CI workflow for automated test execution.

---

## Notes
- This project is an isolated security research and demonstration environment using synthetic HR data.
- Cloud metadata access in `ATK-08` is simulated locally (via `127.0.0.1:8888` or an in-memory synthetic fallback). No real cloud credentials or production metadata services are accessed.
- Deterministic Boundary Routing (`_route_hardened_tool_boundaries()`) is an evaluation-only fallback (`evaluation_mode=True`) used to exercise backend security controls when a small local model does not emit native structured tool calls. Its results verify backend control enforcement and are not treated as evidence of unassisted model-level attack resistance.
- The `SHA-256` telemetry hash chain verifies internal chain consistency (*integrity*) relative to an uncorrupted start state, but does not provide external *authenticity* against an attacker with full file-write privileges who recomputes the entire file from `GENESIS_HASH`.
- Sliding-window rate limiting and heuristic token-budget estimation operate in-memory per Python process and do not use a model-specific BPE tokenizer or distributed state store.
