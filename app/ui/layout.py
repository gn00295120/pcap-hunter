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
    """Top tabs: Upload • Progress • Dashboard • OSINT • Results • Config."""
    tabs = st.tabs(["📤 Upload", "📈 Progress", "📊 Dashboard", "🕵️ OSINT", "📋 Raw Data", "⚙️ Config"])
    return tabs[0], tabs[1], tabs[2], tabs[3], tabs[4], tabs[5]


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


@st.dialog("WHOIS Info")
def show_whois_dialog(target: str):
    from app.utils.common import get_whois_info

    with st.spinner(f"Fetching WHOIS for {target}..."):
        info = get_whois_info(target)

    if not isinstance(info, dict):
        st.error(str(info))
        return

    # Helper to safely get string or first item of list
    def _s(val):
        if isinstance(val, list):
            return str(val[0]) if val else "n/a"
        return str(val) if val else "n/a"

    # Helper to format dates
    def _d(val):
        if isinstance(val, list):
            val = val[0] if val else None
        return str(val).split(" ")[0] if val else "n/a"

    # Header
    st.subheader(f"Domain: {info.get('domain_name', target)}")

    # Key Metrics
    st.text_input("Registrar", value=_s(info.get("registrar")), disabled=True)
    st.text_input("Created", value=_d(info.get("creation_date")), disabled=True)
    st.text_input("Expires", value=_d(info.get("expiration_date")), disabled=True)

    st.divider()

    # Registrant Info
    st.markdown("**Registrant Details**")
    rc1, rc2 = st.columns(2)
    with rc1:
        st.text_input("Name", value=_s(info.get("name")), disabled=True)
        st.text_input("Organization", value=_s(info.get("org")), disabled=True)
    with rc2:
        st.text_input("Email", value=_s(info.get("emails")), disabled=True)
        st.text_input("Country", value=_s(info.get("country")), disabled=True)

    # Location
    if info.get("city") or info.get("state"):
        st.caption(f"Location: {_s(info.get('city'))}, {_s(info.get('state'))}")

    # Name Servers
    if info.get("name_servers"):
        st.markdown("**Name Servers**")
        ns = info["name_servers"]
        if isinstance(ns, list):
            for n in ns:
                st.markdown(f"- `{n}`")
        else:
            st.markdown(f"- `{ns}`")

    st.divider()
    with st.expander("Raw Data"):
        st.json(info)


def render_osint(result_col, osint_data):
    with result_col:
        # Use tabs instead of columns for better space
        tab_ips, tab_doms = st.tabs(["IP Addresses", "Domains"])

        # IPs Tab
        with tab_ips:
            st.caption("Select a row to view WHOIS information.")
            ip_rows = []
            for ip, obj in (osint_data.get("ips") or {}).items():
                vt_attr = (obj.get("vt") or {}).get("data", {}).get("attributes", {})
                vt_rep = vt_attr.get("reputation", "n/a")
                gn = (obj.get("greynoise") or {}).get("classification", "n/a")
                ptr = obj.get("ptr", "n/a")
                ip_rows.append({
                    "IP": ip,
                    "PTR": ptr,
                    "GreyNoise": gn,
                    "VT Rep": vt_rep
                })

            if ip_rows:
                df_ips = pd.DataFrame(ip_rows)
                event = st.dataframe(
                    df_ips,
                    width="stretch",
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key=f"osint_ips_{len(ip_rows)}"
                )
                if event.selection.rows:
                    idx = event.selection.rows[0]
                    target_ip = df_ips.iloc[idx]["IP"]
                    show_whois_dialog(target_ip)
            else:
                st.info("No public IP findings.")

        # Domains Tab
        with tab_doms:
            st.caption("Select a row to view WHOIS information.")
            dom_rows = []
            for dom, obj in (osint_data.get("domains") or {}).items():
                vt_attr = (obj.get("vt") or {}).get("data", {}).get("attributes", {})
                cats = vt_attr.get("categories", "n/a")
                dom_rows.append({
                    "Domain": dom,
                    "VT Categories": str(cats)
                })

            if dom_rows:
                df_doms = pd.DataFrame(dom_rows)
                event = st.dataframe(
                    df_doms,
                    width="stretch",
                    hide_index=True,
                    on_select="rerun",
                    selection_mode="single-row",
                    key=f"osint_doms_{len(dom_rows)}"
                )
                if event.selection.rows:
                    idx = event.selection.rows[0]
                    target_dom = df_doms.iloc[idx]["Domain"]
                    show_whois_dialog(target_dom)
            else:
                st.info("No domain findings.")


def render_report(result_col, report_md):
    with result_col:
        st.markdown("#### LLM Report")
        if report_md:
            st.markdown(report_md)
        else:
            st.caption("No report yet.")
