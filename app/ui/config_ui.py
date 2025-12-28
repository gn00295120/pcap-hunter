import os

import streamlit as st

from app import config as C
from app.utils.config_manager import get_config_manager

# Keys to persist (mapping session_state key -> config file key)
PERSIST_KEYS = {
    "cfg_lm_base_url": "cfg_llm_endpoint",
    "cfg_lm_api_key": "cfg_openai_key",
    "cfg_lm_model": "cfg_llm_model",
    "cfg_otx": "cfg_otx_key",
    "cfg_vt": "cfg_vt_key",
    "cfg_abuseipdb": "cfg_abuseipdb_key",
    "cfg_greynoise": "cfg_greynoise_key",
    "cfg_shodan": "cfg_shodan_key",
    "cfg_limit_packets": "cfg_pyshark_limit",
    "cfg_osint_top_ips": "cfg_osint_top_ips",
    "cfg_osint_cache_enabled": "cfg_osint_cache_enabled",
    "cfg_zeek_bin": "cfg_zeek_bin",
    "cfg_tshark_bin": "cfg_tshark_bin",
}


def init_config_defaults():
    """Initialize config defaults, loading from persistent storage first."""
    # Try to load saved config
    cm = get_config_manager()
    saved_config = cm.load()

    # LLM settings (check saved config first, then env, then defaults)
    _ss_default("cfg_lm_base_url", saved_config.get("cfg_llm_endpoint") or os.getenv("LMSTUDIO_BASE_URL", C.LM_BASE_URL))
    _ss_default("cfg_lm_api_key", saved_config.get("cfg_openai_key") or os.getenv("LMSTUDIO_API_KEY", C.LM_API_KEY))
    _ss_default("cfg_lm_model", saved_config.get("cfg_llm_model") or os.getenv("LMSTUDIO_MODEL", C.LM_MODEL))

    # OSINT keys
    _ss_default("cfg_otx", saved_config.get("cfg_otx_key") or os.getenv("OTX_KEY", C.OTX_KEY))
    _ss_default("cfg_vt", saved_config.get("cfg_vt_key") or os.getenv("VT_KEY", C.VT_KEY))
    _ss_default("cfg_abuseipdb", saved_config.get("cfg_abuseipdb_key") or os.getenv("ABUSEIPDB_KEY", C.ABUSEIPDB_KEY))
    _ss_default("cfg_greynoise", saved_config.get("cfg_greynoise_key") or os.getenv("GREYNOISE_KEY", C.GREYNOISE_KEY))
    _ss_default("cfg_shodan", saved_config.get("cfg_shodan_key") or os.getenv("SHODAN_KEY", C.SHODAN_KEY))

    # Analysis settings
    _ss_default("cfg_limit_packets", saved_config.get("cfg_pyshark_limit") or C.DEFAULT_PYSHARK_LIMIT)
    _ss_default("cfg_do_pyshark", True)
    _ss_default("cfg_do_zeek", True)
    _ss_default("cfg_do_carve", True)
    _ss_default("cfg_pre_count", C.PRECNT_DEFAULT)
    _ss_default("cfg_osint_top_ips", saved_config.get("cfg_osint_top_ips") or C.OSINT_TOP_IPS_DEFAULT)
    _ss_default("cfg_osint_cache_enabled", saved_config.get("cfg_osint_cache_enabled", False))

    # Binary paths
    _ss_default("cfg_zeek_bin", saved_config.get("cfg_zeek_bin") or "")
    _ss_default("cfg_tshark_bin", saved_config.get("cfg_tshark_bin") or "")


def _ss_default(key: str, value):
    if key not in st.session_state:
        st.session_state[key] = value


def save_config() -> bool:
    """Save current session config to persistent storage."""
    cm = get_config_manager()
    config_to_save = {}

    for ss_key, cfg_key in PERSIST_KEYS.items():
        value = st.session_state.get(ss_key)
        if value is not None:
            config_to_save[cfg_key] = value

    try:
        cm.save(config_to_save)
        return True
    except Exception:
        return False


def load_config() -> bool:
    """Load config from persistent storage into session state."""
    cm = get_config_manager()
    try:
        saved_config = cm.load()

        for ss_key, cfg_key in PERSIST_KEYS.items():
            if cfg_key in saved_config and saved_config[cfg_key]:
                st.session_state[ss_key] = saved_config[cfg_key]
        return True
    except Exception:
        return False


def render_config_tab():
    st.markdown("### Configuration")
    st.markdown("#### LM Studio (OpenAI-compatible)")
    c1, c2 = st.columns([2, 1])
    with c1:
        st.session_state["cfg_lm_base_url"] = st.text_input(
            "OpenAI base_url", value=st.session_state.get("cfg_lm_base_url")
        )
        st.session_state["cfg_lm_model"] = st.text_input("Model name", value=st.session_state.get("cfg_lm_model"))
    with c2:
        st.session_state["cfg_lm_api_key"] = st.text_input("API Key", value=st.session_state.get("cfg_lm_api_key"))

    st.markdown("---")
    st.markdown("#### OSINT API Keys (optional)")
    oc1, oc2, oc3 = st.columns(3)
    with oc1:
        st.session_state["cfg_otx"] = st.text_input("OTX", type="password", value=st.session_state.get("cfg_otx"))
        st.session_state["cfg_vt"] = st.text_input("VirusTotal", type="password", value=st.session_state.get("cfg_vt"))
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
    st.markdown("#### Binary Paths (optional)")
    bp1, bp2 = st.columns(2)
    with bp1:
        zeek_path = st.text_input(
            "Zeek Binary Path", value=st.session_state.get("cfg_zeek_bin", ""), placeholder="Auto-detect"
        )
        st.session_state["cfg_zeek_bin"] = zeek_path

        # Check status
        from app.utils.common import find_bin

        resolved_zeek = find_bin("zeek", env_key="ZEEK_BIN", cfg_key="cfg_zeek_bin")
        if resolved_zeek:
            st.success(f"Found: `{resolved_zeek}`")
        else:
            st.error("Not found. Install Zeek or set path.")

    with bp2:
        tshark_path = st.text_input(
            "Tshark Binary Path", value=st.session_state.get("cfg_tshark_bin", ""), placeholder="Auto-detect"
        )
        st.session_state["cfg_tshark_bin"] = tshark_path

        resolved_tshark = find_bin("tshark", cfg_key="cfg_tshark_bin")
        if resolved_tshark:
            st.success(f"Found: `{resolved_tshark}`")
        else:
            st.error("Not found. Install Wireshark/Tshark.")

    st.markdown("---")
    st.markdown("#### Extraction / Analysis")
    st.session_state["cfg_limit_packets"] = st.number_input(
        "PyShark packet limit (0 = no limit)",
        min_value=0,
        value=int(st.session_state.get("cfg_limit_packets", C.DEFAULT_PYSHARK_LIMIT)),
        step=10000,
    )
    tc1, tc2, tc3, tc4 = st.columns(4)
    with tc1:
        st.session_state["cfg_do_pyshark"] = st.checkbox(
            "Run Packet Parsing (Tshark)", value=bool(st.session_state.get("cfg_do_pyshark", True))
        )
    with tc2:
        st.session_state["cfg_do_zeek"] = st.checkbox("Run Zeek", value=bool(st.session_state.get("cfg_do_zeek", True)))
    with tc3:
        st.session_state["cfg_do_carve"] = st.checkbox(
            "Carve HTTP bodies", value=bool(st.session_state.get("cfg_do_carve", True))
        )
    with tc4:
        st.session_state["cfg_pre_count"] = st.checkbox(
            "Pre-count packets", value=bool(st.session_state.get("cfg_pre_count", C.PRECNT_DEFAULT))
        )

    osint_col1, osint_col2 = st.columns([3, 1])
    with osint_col1:
        st.session_state["cfg_osint_top_ips"] = st.number_input(
            "OSINT: Top N public IPs to enrich (0 = all)",
            min_value=0,
            max_value=1000,
            value=int(st.session_state.get("cfg_osint_top_ips", 50)),
            step=5,
        )
    with osint_col2:
        st.session_state["cfg_osint_cache_enabled"] = st.checkbox(
            "Enable OSINT Cache",
            value=bool(st.session_state.get("cfg_osint_cache_enabled", False)),
            help="Cache OSINT API responses to speed up repeated analysis. Disable for fresh results.",
        )

    st.markdown("---")
    st.markdown("#### Save / Load Configuration")
    st.caption("Save your settings to persist across sessions. API keys are encrypted.")

    col_buttons = st.columns([1, 1, 1, 1, 4])
    with col_buttons[0]:
        if st.button("Save Config", type="primary"):
            if save_config():
                st.success("Config saved!")
            else:
                st.error("Failed to save config.")
    with col_buttons[1]:
        if st.button("Load Config"):
            if load_config():
                st.success("Config loaded!")
                st.rerun()
            else:
                st.error("Failed to load config.")
    with col_buttons[2]:
        if st.button("Apply & Rerun"):
            st.rerun()
    with col_buttons[3]:
        if st.button("Reset Defaults"):
            for k in list(st.session_state.keys()):
                if k.startswith("cfg_"):
                    del st.session_state[k]
            # Clear saved config
            get_config_manager().clear()
            init_config_defaults()
            st.success("Config reset to defaults.")
            st.rerun()

    st.markdown("---")
    with st.expander("Runtime Logs"):
        logs = st.session_state.get("runtime_logs", [])
        if logs:
            st.code("\n".join(logs))
        else:
            st.info("No runtime logs.")
