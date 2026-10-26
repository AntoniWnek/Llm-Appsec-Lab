import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path when running via `streamlit run src/app.py`
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
from src.agent import ask_hr_agent
from src.init_db import init_database
from src.tools import extract_cv_text

st.set_page_config(
    page_title="LLM AppSec Lab - HR Copilot",
    page_icon="🛡️",
    layout="wide",
)

if "messages" not in st.session_state:
    st.session_state.messages = []

# --- SIDEBAR: Engine, Security Controls & CV Upload ---
with st.sidebar:
    st.title("Security Controls")

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
        options=["🔴 Vulnerable (Raw SQL & No Guardrails)", "🟢 Hardened (Defense-in-Depth)"],
        index=0,
    )
    security_mode = "VULNERABLE" if "Vulnerable" in security_mode_label else "HARDENED"

    st.divider()
    st.subheader("Candidate CV Upload")
    uploaded_cv = st.file_uploader(
        "Upload candidate CV (.txt or .pdf)",
        type=["txt", "pdf"],
        help="Used to test Indirect Prompt Injection (XPIA) via untrusted documents.",
    )

    cv_text = ""
    if uploaded_cv is not None:
        try:
            cv_text = extract_cv_text(uploaded_cv)
            with st.expander("Preview Extracted CV Text"):
                st.text(cv_text[:1000] + ("..." if len(cv_text) > 1000 else ""))
        except ValueError as err:
            st.error(f"CV Upload Error: {err}")

    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Clear Chat", use_container_width=True):
            st.session_state.messages = []
            st.rerun()
    with col2:
        if st.button("Reset DB", use_container_width=True):
            init_database()
            st.toast("Database reset to default state!")

# --- MAIN AREA: HR Copilot Chat ---
st.title("Enterprise HR Copilot — LLM Application Security Lab")
st.caption(
    f"**Engine:** `{selected_provider.upper()}` | "
    f"**Active Mode:** `{security_mode}` | "
    f"**CV Attached:** `{'Yes (' + uploaded_cv.name + ')' if uploaded_cv else 'No'}`"
)

# Render existing chat messages
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])
        if msg.get("meta"):
            meta = msg["meta"]
            with st.expander(f"Under the Hood | Status: {meta['status']} | Latency: {meta['latency_ms']} ms"):
                st.write(f"**Model:** `{meta['model']}` | **Mode:** `{meta['security_mode']}`")
                if meta["tool_trace"]:
                    st.write("**Executed Tool Calls:**")
                    st.json(meta["tool_trace"])
                else:
                    st.write("*No database tools invoked during this turn.*")

# Chat input
if user_prompt := st.chat_input("Ask the HR Copilot about candidates or summarize the uploaded CV..."):
    st.session_state.messages.append({"role": "user", "content": user_prompt})
    with st.chat_message("user"):
        st.markdown(user_prompt)

    with st.chat_message("assistant"):
        with st.spinner(f"HR Copilot ({selected_provider}) is thinking..."):
            result = ask_hr_agent(
                user_prompt=user_prompt,
                cv_text=cv_text,
                security_mode=security_mode,
                provider=selected_provider,
            )

        st.markdown(result["answer"])

        with st.expander(f"Under the Hood | Status: {result['status']} | Latency: {result['latency_ms']} ms"):
            st.write(f"**Model:** `{result['model']}` | **Mode:** `{result['security_mode']}`")
            if result["tool_trace"]:
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
