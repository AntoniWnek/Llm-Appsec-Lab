import json
import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path when running via `streamlit run src/app.py`
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import streamlit as st
from src.agent import ask_hr_agent
from src.init_db import init_database
from src.telemetry import clear_telemetry_events, read_telemetry_events
from src.tools import extract_cv_text

BENCHMARK_JSON_PATH = ROOT_DIR / "data" / "benchmark_results.json"

st.set_page_config(
    page_title="LLM AppSec Lab - HR Copilot & SOC",
    page_icon="🛡️",
    layout="wide",
)

# Compact sidebar CSS to eliminate vertical scrollbar, reduce top padding, 
# and increase sidebar subheader size to match title size without default margins.
st.markdown(
    """
    <style>
        section[data-testid="stSidebar"] div.block-container {
            padding-top: 1rem !important;
            padding-bottom: 1rem !important;
        }
        div[data-testid="stSidebarUserContent"] {
            padding-top: 1rem !important;
        }
        section[data-testid="stSidebar"] hr {
            margin-top: 0.6rem !important;
            margin-bottom: 0.6rem !important;
        }
        div.block-container {
            padding-top: 2rem !important;
        }
        /* Zwiększenie rozmiaru subheadera w sidebarze do rozmiaru tytułu */
        section[data-testid="stSidebar"] h3 {
            font-size: 2rem !important;
            font-weight: 700 !important;
            line-height: 1.2 !important;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

if "messages" not in st.session_state:
    st.session_state.messages = []

# --- SIDEBAR: Engine, Security Controls & CV Upload ---
with st.sidebar:
    st.subheader("Security Controls")

    default_provider = os.getenv("LLM_PROVIDER", "ollama").lower()
    provider_index = 0 if default_provider == "ollama" else 1

    provider_label = st.selectbox(
        "LLM Engine Provider:",
        options=["Local Ollama (Offline)", "Google Gemini API (Cloud)"],
        index=provider_index,
        help="Run completely offline via local Ollama models or connect to Google Gemini API.",
    )
    selected_provider = "ollama" if "Ollama" in provider_label else "gemini"

    security_mode_label = st.radio(
        "Select Security Mode:",
        options=["Vulnerable (Raw SQL & Flawed Filters)", "Hardened (Defense-in-Depth)"],
        index=0,
    )
    security_mode = "VULNERABLE" if "Vulnerable" in security_mode_label else "HARDENED"

    with st.expander("Mode Architecture Details", expanded=False):
        if security_mode == "HARDENED":
            st.caption(
                "Active Defenses:\n"
                "1. Input Normalization & Heuristic Guardrail\n"
                "2. XML <untrusted_cv_data> Sandboxing\n"
                "3. Pydantic Validation & Parameterized SQL\n"
                "4. SQLite C-Driver Authorizer (SQLITE_DENY)\n"
                "5. Output DLP Canary Scanner & Markdown Sanitizer"
            )
        else:
            st.caption(
                "Vulnerable Mode Active:\n"
                "Exposes run_raw_sql with bypassable legacy filters, TOCTOU bugs, and unvalidated Markdown rendering."
            )

    st.divider()
    st.markdown("**Candidate CV Upload**")
    uploaded_cv = st.file_uploader(
        "Upload candidate CV (.txt or .pdf)",
        type=["txt", "pdf"],
        label_visibility="collapsed",
        help="Used to test Indirect Prompt Injection (XPIA) via untrusted documents.",
    )

    cv_text = ""
    if uploaded_cv is not None:
        try:
            cv_text = extract_cv_text(uploaded_cv)
            with st.expander("Lab X-Ray: Raw Stream Extracted by pypdf"):
                st.caption(
                    "Reveals off-canvas (-5000, -5000) or white-on-white PDF text that is invisible to human recruiters but ingested by the LLM."
                )
                st.text(cv_text[:1200] + ("..." if len(cv_text) > 1200 else ""))
        except ValueError as err:
            st.error(f"CV Upload Error: {err}")

    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Clear Chat", width="stretch"):
            st.session_state.messages = []
            st.rerun()
    with col2:
        if st.button("Reset DB", width="stretch"):
            init_database()
            st.toast("Database reset to default state.")

    if st.button("Clear SIEM Telemetry Logs", width="stretch"):
        clear_telemetry_events()
        st.toast("Telemetry logs cleared.")
        st.rerun()

# --- MAIN AREA HEADER ---
st.title("Enterprise HR Copilot — LLM Application Security Lab")
st.caption(
    f"**Engine:** `{selected_provider.upper()}` | "
    f"**Active Mode:** `{security_mode}` | "
    f"**CV Attached:** `{'Yes (' + uploaded_cv.name + ')' if uploaded_cv else 'No'}`"
)

tab_chat, tab_soc = st.tabs(
    [
        "HR Copilot Chat (Red / Blue Playground)",
        "SOC Telemetry & Benchmark Dashboard",
    ]
)

# =====================================================================
# TAB 1: Interactive HR Copilot Chat
# =====================================================================
with tab_chat:
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg.get("meta"):
                meta = msg["meta"]
                block_reason = meta.get("block_reason") or "NONE"
                expander_label = (
                    f"Under the Hood | Status: {meta['status']} | "
                    f"Block Reason: {block_reason} | Latency: {meta['latency_ms']} ms"
                )
                with st.expander(expander_label):
                    st.write(
                        f"**Model:** `{meta['model']}` | **Mode:** `{meta['security_mode']}` | "
                        f"**Block Reason:** `{block_reason}`"
                    )
                    if meta.get("tool_trace"):
                        st.write("**Executed Tool Calls:**")
                        st.json(meta["tool_trace"])
                    else:
                        st.write("*No database tools invoked during this turn.*")

    if user_prompt := st.chat_input("Ask the HR Copilot about candidates or summarize the uploaded CV..."):
        st.session_state.messages.append({"role": "user", "content": user_prompt})
        with st.chat_message("user"):
            st.markdown(user_prompt)

        with st.chat_message("assistant"):
            with st.spinner(f"HR Copilot ({selected_provider}) is processing..."):
                result = ask_hr_agent(
                    user_prompt=user_prompt,
                    cv_text=cv_text,
                    security_mode=security_mode,
                    provider=selected_provider,
                    record_telemetry=True,
                )

            st.markdown(result["answer"])
            block_reason = result.get("block_reason") or "NONE"
            expander_label = (
                f"Under the Hood | Status: {result['status']} | "
                f"Block Reason: {block_reason} | Latency: {result['latency_ms']} ms"
            )
            with st.expander(expander_label):
                st.write(
                    f"**Model:** `{result['model']}` | **Mode:** `{result['security_mode']}` | "
                    f"**Block Reason:** `{block_reason}`"
                )
                if result.get("tool_trace"):
                    st.write("**Executed Tool Calls:**")
                    st.json(result["tool_trace"])
                else:
                    st.write("*No database tools invoked during this turn.*")

        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": result["answer"],
                "meta": result,
            }
        )

# =====================================================================
# TAB 2: SOC Telemetry & Benchmark Analytics Dashboard
# =====================================================================
with tab_soc:
    st.subheader("Live SIEM Security Event Telemetry (data/telemetry.jsonl)")

    events = read_telemetry_events()
    if not events:
        st.info(
            "No live telemetry events recorded yet. Interact with the HR Copilot Chat or run `python src/run_benchmark.py` to populate SIEM logs."
        )
    else:
        df = pd.DataFrame(events)

        total_events = len(df)
        blocked_count = int((df["status"] == "BLOCKED").sum())
        canary_leaks = int(df["canary_leaked"].sum()) if "canary_leaked" in df.columns else 0
        exfil_beacons = (
            int(df["exfil_beacon_rendered"].sum()) if "exfil_beacon_rendered" in df.columns else 0
        )
        avg_lat = round(float(df["latency_ms"].mean()), 1) if "latency_ms" in df.columns else 0.0

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total SIEM Events", total_events)
        k2.metric("Blocked Requests (HIGH)", blocked_count)
        k3.metric("Canary Token Leaks (CRITICAL)", canary_leaks)
        k4.metric("Exfil Beacons Triggered", exfil_beacons)
        k5.metric("Mean Latency (ms)", f"{avg_lat} ms")

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown("##### Events by SOC Severity Level")
            severity_counts = df["severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
            st.bar_chart(severity_counts.set_index("Severity"))

        with chart_col2:
            st.markdown("##### Active Defense Layer Triggers (block_reason)")
            blocked_df = df[df["block_reason"] != "NONE"]
            if blocked_df.empty:
                st.caption("No block triggers recorded yet.")
            else:
                reason_counts = (
                    blocked_df["block_reason"]
                    .value_counts()
                    .rename_axis("Defense Layer")
                    .reset_index(name="Blocks")
                )
                st.bar_chart(reason_counts.set_index("Defense Layer"))

        st.markdown("##### Filterable SIEM Event Log")
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            mode_filter = st.multiselect(
                "Filter by Security Mode:",
                options=sorted(df["security_mode"].unique().tolist()),
                default=sorted(df["security_mode"].unique().tolist()),
            )
        with f_col2:
            sev_filter = st.multiselect(
                "Filter by Severity:",
                options=sorted(df["severity"].unique().tolist()),
                default=sorted(df["severity"].unique().tolist()),
            )

        filtered_df = df[
            df["security_mode"].isin(mode_filter) & df["severity"].isin(sev_filter)
        ].sort_values(by="timestamp_utc", ascending=False)

        display_cols = [
            col
            for col in [
                "timestamp_utc",
                "event_id",
                "severity",
                "security_mode",
                "status",
                "block_reason",
                "canary_leaked",
                "exfil_beacon_rendered",
                "schema_leaked",
                "tools_invoked",
                "latency_ms",
                "prompt_preview",
            ]
            if col in filtered_df.columns
        ]
        st.dataframe(filtered_df[display_cols], width="stretch", hide_index=True)

    st.divider()
    st.subheader("Empirical Benchmark Evaluation (data/benchmark_results.json)")

    if not BENCHMARK_JSON_PATH.exists():
        st.info("Benchmark file not found. Run `python src/run_benchmark.py` to generate empirical metrics.")
    else:
        try:
            bench_data = json.loads(BENCHMARK_JSON_PATH.read_text(encoding="utf-8"))
            meta = bench_data.get("metadata", {})
            summary = bench_data.get("summary", {})
            vuln_s = summary.get("VULNERABLE", {})
            hard_s = summary.get("HARDENED", {})

            st.caption(
                f"**Last Benchmark Run:** `{meta.get('timestamp_utc', 'N/A')}` | "
                f"**Model:** `{meta.get('model', 'N/A')}` | "
                f"**Config Version:** `{meta.get('config_version', 'N/A')}`"
            )

            b1, b2, b3, b4 = st.columns(4)
            b1.metric(
                "Vulnerable ASR (Attack Success)",
                f"{vuln_s.get('attack_success_rate_pct', 0)}%",
                f"{vuln_s.get('successful_attacks', 0)}/{vuln_s.get('total_attacks', 0)} exploited",
                delta_color="inverse",
            )
            b2.metric(
                "Hardened ASR (Attack Success)",
                f"{hard_s.get('attack_success_rate_pct', 0)}%",
                f"{hard_s.get('mitigated_attacks', 0)}/{hard_s.get('total_attacks', 0)} mitigated",
                delta_color="normal",
            )
            b3.metric(
                "Hardened False Positive Rate (FPR)",
                f"{hard_s.get('false_positive_rate_pct', 0)}%",
                f"{hard_s.get('allowed_benign', 0)}/{hard_s.get('total_benign', 0)} benign allowed",
            )
            b4.metric(
                "Hardened Mean Latency",
                f"{hard_s.get('avg_latency_ms', 0)} ms",
            )

            results_list = bench_data.get("results", [])
            if results_list:
                bench_df = pd.DataFrame(results_list)
                st.markdown("##### Per-Test-Case Benchmark Matrix")
                st.dataframe(
                    bench_df[
                        [
                            "id",
                            "category",
                            "security_mode",
                            "scenario",
                            "owasp_2025",
                            "outcome",
                            "block_reason",
                            "tools_called",
                            "latency_ms",
                        ]
                    ],
                    width="stretch",
                    hide_index=True,
                )
        except Exception as err:
            st.error(f"Failed to load benchmark results: {err}")
