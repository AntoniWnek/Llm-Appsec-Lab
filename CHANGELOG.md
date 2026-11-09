# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This repository is maintained as a continuously evolving security research lab and does not currently publish formal, version-tagged releases. Therefore, completed changes are documented chronologically under `[Unreleased]`, grouped by engineering milestone.

---

## [Unreleased]

### Milestone 3: Architectural Boundary Hardening & Deterministic Evaluation (2026-11)

#### Added
- Added `docs/Engineering_Log.md` documenting the project's architectural evolution using the *Problem → Technical Decision → Engineering Rationale → Verification* framework.
- Added an MIT `LICENSE`, including the standard warranty and liability disclaimers.
- Expanded `docs/Threat_Model.md` to cover three distinct threat domains: **Internal Recruiter**, **External Candidate**, and **Execution Environment / Runtime**.
- Introduced benchmark outcome classification in `src/run_benchmark.py`, distinguishing `DETERMINISTIC_CODE_CONTROL` from `PROBABILISTIC_MODEL_BEHAVIOR`.
- Expanded automated test coverage in `tests/test_security_controls.py` to **42 executed test cases across 14 test functions**: 5 unit/functional cases, 34 negative boundary cases, and 3 end-to-end integration cases using mocked LLM responses.
- Documented residual security risks and scope limitations, including model-level semantic misclassification, application-layer versus network-layer SSRF protection, and the limitations of XML-based untrusted-content isolation.

#### Changed
- **Shifted Primary Enforcement to Tool & Data Boundaries:** Removed SQL and table-name keyword blacklists from Layer 1 (`inspect_user_input`). Adversarial prompts can now reach downstream security boundaries instead of being trivially rejected at the chat-input layer. This allows the evaluation to exercise actual application controls, including tool authorization (`BLOCKED_UNAUTHORIZED_TOOL`), Pydantic validation (`BLOCKED_BY_PYDANTIC`), and SQLite authorization (`BLOCKED_BY_AUTHORIZER`).
- **Implemented Task-Based Zero-Tool Scoping for Document Summarization:** Updated `src/agent.py` so that when an untrusted CV is attached in `Hardened` mode (`cv_attached=True`), the orchestrator removes all tool definitions for that LLM turn (`active_tools = []`, passed to the provider as `tools=None`). This prevents the model from invoking application tools while processing untrusted document content, independently of the instructions contained within `<untrusted_cv_data>` delimiters.
- **Replaced Hardcoded DLP Entities with Dynamic Database Loading:** Refactored `inspect_and_sanitize_output()` in `src/guardrails.py` to dynamically load protected executive names, compensation figures, and markers directly from the `board_salaries` SQLite table (`_load_protected_entities_from_db()`), eliminating hardcoded PII/salary strings in filter code.
- **Generalized Document-Boundary & Media Sanitization:** Replaced hardcoded CV delimiter string splitting with generic boundary pattern matching and expanded `MARKDOWN_IMAGE_RE` to neutralize reference-style Markdown images, `data:`/`file:` URIs, and raw HTML active tags (`<img>`, `<iframe>`, `<script>`, `<object>`, `<embed>`).

#### Fixed
- Corrected optional status-filter handling in `CandidateSearchParams` to normalize generic filler values (`"all"`, `"any"`, `"none"`) emitted by smaller local LLMs before validation and SQL query construction, preventing unintended empty query results.

#### Security
- Expanded negative boundary tests to cover IPv4-mapped IPv6 representations of cloud metadata addresses (`::ffff:169.254.169.254`), SQLite subqueries, unauthorized `PRAGMA` statements, and oversized file uploads.
- Strengthened evaluation of tool-scope restrictions and untrusted-document handling in `Hardened` mode.

---

### Milestone 2: Second-Order Stored Injection & Agentic SSRF Boundaries (2026-10)

#### Added
- **Scenario 5 (`ATK-07`) — Second-Order Stored Prompt Injection:** Introduced a synthetic candidate record (`Victor Reznov`) in SQLite (`src/init_db.py`) containing a dormant prompt-injection payload in the `key_skills` field. The record is isolated from benign benchmark cases (`BEN-01`–`BEN-03`).
- **Scenario 6 (`ATK-08`) — Agentic SSRF (Simulated Cloud Metadata Access):** Added the `fetch_portfolio_url` tool and an isolated mock metadata response at `169.254.169.254`, returning synthetic AWS STS-style credentials (`ASIA-HR-PROD-9921`).
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
- Added a local HTTP listener (`src/attacker_listener.py`) on port 8888 to capture simulated Markdown image-beacon callbacks.
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
- Cloud metadata access in `ATK-08` is simulated using synthetic responses. No real cloud credentials or production metadata services are accessed.
- LLM-based attack outcomes may vary depending on the model provider, model version, configuration, and execution conditions.
- XML delimiters and prompt-level instructions are isolation aids, not independent security boundaries.
- Application-layer URL validation does not replace network-level egress restrictions. DNS rebinding, redirects, and other network-level concerns must be considered separately.
- The project demonstrates selected attack paths and mitigations; it does not claim to eliminate all prompt-injection vulnerabilities or provide production-ready HR infrastructure.
