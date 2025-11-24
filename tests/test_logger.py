import streamlit as st

from app.utils.logger import log_runtime_error


def test_log_runtime_error():
    # Mock session state if needed, but streamlit usually handles it in tests if configured right.
    # If not, we might need to mock st.session_state.
    # Streamlit's session state is a bit tricky in tests without streamlit context.
    # But let's try basic usage.

    # Reset
    if "runtime_logs" in st.session_state:
        del st.session_state["runtime_logs"]

    log_runtime_error("Test error")

    assert "runtime_logs" in st.session_state
    assert len(st.session_state["runtime_logs"]) == 1
    assert "Test error" in st.session_state["runtime_logs"][0]
