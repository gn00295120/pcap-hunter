from __future__ import annotations

import pandas as pd
import streamlit as st

from app.utils.common import is_public_ipv4
from app.utils.export import (
    export_dataframe_to_csv,
    export_dataframe_to_json,
    export_to_csv,
    export_to_json,
    generate_export_filename,
)


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


def render_export_buttons(data, prefix: str, key_suffix: str = "", is_dataframe: bool = False):
    """
    Render CSV and JSON export buttons for data.

    Args:
        data: Data to export (list of dicts or DataFrame)
        prefix: Filename prefix (e.g., "flows", "osint")
        key_suffix: Optional suffix for unique button keys
        is_dataframe: Whether data is a pandas DataFrame
    """
    if data is None or (is_dataframe and data.empty) or (not is_dataframe and not data):
        return

    col1, col2, _ = st.columns([1, 1, 4])

    with col1:
        if is_dataframe:
            csv_data = export_dataframe_to_csv(data)
        else:
            csv_data = export_to_csv(data)

        st.download_button(
            label="CSV",
            data=csv_data,
            file_name=generate_export_filename(prefix, "csv"),
            mime="text/csv",
            key=f"export_csv_{prefix}_{key_suffix}",
        )

    with col2:
        if is_dataframe:
            json_data = export_dataframe_to_json(data)
        else:
            json_data = export_to_json(data)

        st.download_button(
            label="JSON",
            data=json_data,
            file_name=generate_export_filename(prefix, "json"),
            mime="application/json",
            key=f"export_json_{prefix}_{key_suffix}",
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
                        render_export_buttons(df, f"zeek_{name}", key_suffix=name, is_dataframe=True)
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
                render_export_buttons(df[cols], "carved_payloads", key_suffix="carved", is_dataframe=True)
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
                render_export_buttons(df_ips, "osint_ips", key_suffix="ips", is_dataframe=True)
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
                render_export_buttons(df_doms, "osint_domains", key_suffix="doms", is_dataframe=True)
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


def render_flows(result_col, flows: list[dict] | None):
    """Render flows table with export buttons."""
    with result_col:
        with st.expander("Flow Data", expanded=False):
            if flows:
                df = pd.DataFrame(flows)
                # Select key columns if available
                display_cols = ["src", "dst", "sport", "dport", "proto", "count"]
                display_cols = [c for c in display_cols if c in df.columns]
                if display_cols:
                    render_export_buttons(df[display_cols], "flows", key_suffix="flows", is_dataframe=True)
                    st.dataframe(df[display_cols], width="stretch", hide_index=True)
                else:
                    render_export_buttons(df, "flows", key_suffix="flows_all", is_dataframe=True)
                    st.dataframe(df, width="stretch", hide_index=True)
            else:
                st.caption("No flow data available.")


def render_ja3(result_col, ja3_df, ja3_analysis: dict | None):
    """Render JA3 fingerprint analysis results."""
    with result_col:
        with st.expander("JA3 TLS Fingerprints", expanded=bool(ja3_analysis and ja3_analysis.get("malware_detected"))):
            if ja3_analysis and ja3_analysis.get("total_tls_sessions", 0) > 0:
                # Summary metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("TLS Sessions", ja3_analysis.get("total_tls_sessions", 0))
                with col2:
                    st.metric("Unique JA3", ja3_analysis.get("unique_ja3", 0))
                with col3:
                    unknown = ja3_analysis.get("unknown_ja3", 0)
                    st.metric("Unknown", unknown)
                with col4:
                    if ja3_analysis.get("malware_detected"):
                        st.metric("Malware Detected", "YES", delta="Alert", delta_color="inverse")
                    else:
                        st.metric("Malware Detected", "No")

                # Malware warning
                if ja3_analysis.get("malware_detected"):
                    st.error("Malware JA3 fingerprints detected!")
                    malware_list = ja3_analysis.get("malware_ja3", [])
                    for m in malware_list:
                        st.warning(f"**{m.get('ja3_client')}** detected: {m.get('src')} -> {m.get('dst')}")

                # Top clients
                top_clients = ja3_analysis.get("top_clients", {})
                if top_clients:
                    st.markdown("**Top TLS Clients:**")
                    for client, count in list(top_clients.items())[:5]:
                        st.text(f"  {client}: {count}")

                # Full table
                if ja3_df is not None and not ja3_df.empty:
                    st.markdown("---")
                    display_cols = ["src", "dst", "server_name", "ja3", "ja3_client", "ja3_malware"]
                    display_cols = [c for c in display_cols if c in ja3_df.columns]
                    if display_cols:
                        render_export_buttons(ja3_df[display_cols], "ja3", key_suffix="ja3", is_dataframe=True)
                        st.dataframe(ja3_df[display_cols], width="stretch", hide_index=True)
            else:
                st.caption("No TLS/JA3 data available. Run analysis with PCAP containing TLS traffic.")


def render_report(result_col, report_md):
    with result_col:
        st.markdown("#### LLM Report")
        if report_md:
            st.markdown(report_md)
        else:
            st.caption("No report yet.")
