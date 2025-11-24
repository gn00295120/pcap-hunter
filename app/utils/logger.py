from datetime import datetime

import streamlit as st


def log_runtime_error(msg: str):
    """Log a runtime error to the session state."""
    if "runtime_logs" not in st.session_state:
        st.session_state["runtime_logs"] = []

    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state["runtime_logs"].append(f"[{timestamp}] {msg}")
