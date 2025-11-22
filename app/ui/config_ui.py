import os

import streamlit as st

from app import config as C


def init_config_defaults():
    _ss_default("cfg_lm_base_url", os.getenv("LMSTUDIO_BASE_URL", C.LM_BASE_URL))
    _ss_default("cfg_lm_api_key",  os.getenv("LMSTUDIO_API_KEY", C.LM_API_KEY))
    _ss_default("cfg_lm_model",    os.getenv("LMSTUDIO_MODEL", C.LM_MODEL))

    _ss_default("cfg_otx",        os.getenv("OTX_KEY", C.OTX_KEY))
    _ss_default("cfg_vt",         os.getenv("VT_KEY", C.VT_KEY))
    _ss_default("cfg_abuseipdb",  os.getenv("ABUSEIPDB_KEY", C.ABUSEIPDB_KEY))
    _ss_default("cfg_greynoise",  os.getenv("GREYNOISE_KEY", C.GREYNOISE_KEY))
    _ss_default("cfg_shodan",     os.getenv("SHODAN_KEY", C.SHODAN_KEY))

    _ss_default("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)
    _ss_default("cfg_do_pyshark", True)
    _ss_default("cfg_do_zeek", True)
    _ss_default("cfg_do_carve", True)
    _ss_default("cfg_pre_count", C.PRECNT_DEFAULT)
    _ss_default("cfg_osint_top_ips", C.OSINT_TOP_IPS_DEFAULT)

def _ss_default(key: str, value):
    if key not in st.session_state:
        st.session_state[key] = value

def render_config_tab():
    st.markdown("### Configuration")
    st.markdown("#### LM Studio (OpenAI-compatible)")
    c1, c2 = st.columns([2, 1])
    with c1:
        st.session_state["cfg_lm_base_url"] = st.text_input(
            "OpenAI base_url", value=st.session_state.get("cfg_lm_base_url")
        )
        st.session_state["cfg_lm_model"] = st.text_input(
            "Model name", value=st.session_state.get("cfg_lm_model")
        )
    with c2:
        st.session_state["cfg_lm_api_key"] = st.text_input(
            "API Key", value=st.session_state.get("cfg_lm_api_key")
        )

    st.markdown("---")
    st.markdown("#### OSINT API Keys (optional)")
    oc1, oc2, oc3 = st.columns(3)
    with oc1:
        st.session_state["cfg_otx"] = st.text_input(
            "OTX", type="password", value=st.session_state.get("cfg_otx")
        )
        st.session_state["cfg_vt"] = st.text_input(
            "VirusTotal", type="password", value=st.session_state.get("cfg_vt")
        )
    with oc2:
        st.session_state["cfg_abuseipdb"] = st.text_input(
            "AbuseIPDB", type="password", value=st.session_state.get("cfg_abuseipdb")
        )
        st.session_state["cfg_greynoise"] = st.text_input(
            "GreyNoise", type="password", value=st.session_state.get("cfg_greynoise")
        )
    with oc3:
        st.session_state["cfg_shodan"] = st.text_input(
            "Shodan", type="password", value=st.session_state.get("cfg_shodan")
        )

    st.markdown("---")
    st.markdown("#### Extraction / Analysis")
    st.session_state["cfg_limit_packets"] = st.number_input(
        "PyShark packet limit (0 = no limit)",
        min_value=0,
        value=int(st.session_state.get("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)),
        step=10000
    )
    tc1, tc2, tc3, tc4 = st.columns(4)
    with tc1:
        st.session_state["cfg_do_pyshark"] = st.checkbox(
            "Run PyShark", value=bool(st.session_state.get("cfg_do_pyshark", True))
        )
    with tc2:
        st.session_state["cfg_do_zeek"] = st.checkbox(
            "Run Zeek", value=bool(st.session_state.get("cfg_do_zeek", True))
        )
    with tc3:
        st.session_state["cfg_do_carve"] = st.checkbox(
            "Carve HTTP bodies", value=bool(st.session_state.get("cfg_do_carve", True))
        )
    with tc4:
        st.session_state["cfg_pre_count"] = st.checkbox(
            "Pre-count packets", value=bool(st.session_state.get("cfg_pre_count", C.PRECNT_DEFAULT))
        )

    st.session_state["cfg_osint_top_ips"] = st.number_input(
        "OSINT: Top N public IPs to enrich (0 = all)",
        min_value=0, max_value=1000,
        value=int(st.session_state.get("cfg_osint_top_ips", 50)),
        step=5
    )

    st.caption("Changes are saved immediately in Session State.")
    col_buttons = st.columns([1,1,6])
    with col_buttons[0]:
        if st.button("Apply & Rerun"):
            st.rerun()
    with col_buttons[1]:
        if st.button("Reset to Defaults"):
            for k in list(st.session_state.keys()):
                if k.startswith("cfg_"):
                    del st.session_state[k]
            init_config_defaults()
            st.success("Config reset to defaults.")
            st.rerun()
