from __future__ import annotations

import pandas as pd
import streamlit as st

from app.utils.common import is_public_ipv4


def inject_css():
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; padding-bottom: 2rem; }
        .stTabs [role="tablist"] { gap: .5rem; }
        .stTabs [role="tab"] { padding: .45rem .9rem; border-radius: 8px; }
        .stButton>button { border-radius: 10px; }
        .phase-row .stButton>button { height: 38px; }
        .phase-row .stProgress { margin-top: 6px; }
        .section-title { margin-top: .75rem; margin-bottom: .5rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def make_tabs():
    """Top tabs: Upload • Progress • Results • Config."""
    tabs = st.tabs(["📤 Upload", "📈 Progress", "📊 Results", "⚙️ Config"])
    return tabs[0], tabs[1], tabs[2], tabs[3]


def make_progress_panel(container):
    with container:
        st.markdown("### Progress")
        return st.container()


def make_results_panel(container):
    with container:
        st.markdown("### Results")
        return st.container()


# ---------------- Results renderers ----------------


def render_overview(result_col, features):
    with result_col:
        st.markdown("#### Overview")
        feats = features or {"flows": [], "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "ja3": []}}
        row = {
            "Public IPs": len([ip for ip in feats["artifacts"].get("ips", []) if is_public_ipv4(ip)]),
            "Domains": len(feats["artifacts"].get("domains", [])),
            "Flows": len(feats.get("flows", [])),
            "Carved Bodies": len(
                feats["artifacts"].get("hashes", []) if isinstance(feats.get("artifacts", {}), dict) else []
            ),
        }
        df = pd.DataFrame([row]).rename(index={0: ""})
        st.dataframe(df, width="stretch", hide_index=True)


def render_zeek(result_col, zeek_tables):
    with result_col:
        if zeek_tables:
            st.markdown("#### Zeek logs")
            names = sorted(zeek_tables.keys())
            tabs = st.tabs(names)
            for i, name in enumerate(names):
                with tabs[i]:
                    df = zeek_tables.get(name)
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        st.dataframe(df, width="stretch", hide_index=True)
                    else:
                        st.caption("No rows.")
        else:
            st.caption("No Zeek logs loaded.")


def render_carved(result_col, carved):
    with result_col:
        with st.expander("Carved HTTP payloads", expanded=bool(carved)):
            if carved:
                df = pd.DataFrame(carved)
                cols = ["time", "tcp_stream", "content_type", "content_length", "sha256", "path"]
                cols = [c for c in cols if c in df.columns]
                st.dataframe(df[cols], width="stretch", hide_index=True)
            else:
                st.caption("No HTTP payloads carved.")


def render_osint(result_col, osint_data):
    with result_col:
        with st.expander("OSINT findings", expanded=bool(osint_data.get("ips") or osint_data.get("domains"))):
            cols = st.columns(2)
            with cols[0]:
                st.write("**IPs**")
                for ip, obj in (osint_data.get("ips") or {}).items():
                    vt_attr = (obj.get("vt") or {}).get("data", {}).get("attributes", {})
                    vt_rep = vt_attr.get("reputation", "n/a")
                    gn = (obj.get("greynoise") or {}).get("classification", "n/a")
                    st.markdown(f"- `{ip}` — GN: {gn}, VT rep: {vt_rep}")
            with cols[1]:
                st.write("**Domains**")
                for dom, obj in (osint_data.get("domains") or {}).items():
                    vt_attr = (obj.get("vt") or {}).get("data", {}).get("attributes", {})
                    cats = vt_attr.get("categories", "n/a")
                    st.markdown(f"- `{dom}` — VT cat: {cats}")


def render_report(result_col, report_md):
    with result_col:
        st.markdown("#### LLM Report")
        if report_md:
            st.markdown(report_md)
        else:
            st.caption("No report yet.")
