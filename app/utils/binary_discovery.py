from __future__ import annotations

import os
import shutil
from pathlib import Path


def find_bin(name: str, env_key: str = "", cfg_key: str = "") -> str | None:
    """
    Find a binary by name, checking:
    1. Streamlit session state config (if cfg_key provided)
    2. Environment variable (if env_key provided)
    3. PATH
    4. Common macOS locations
    """
    # 1. Config
    if cfg_key:
        try:
            import streamlit as st

            val = st.session_state.get(cfg_key)
            if val and Path(val).is_file():
                return val
        except ImportError:
            pass

    # 2. Env var
    if env_key:
        val = os.environ.get(env_key)
        if val and Path(val).is_file():
            return val

    # 3. PATH
    path = shutil.which(name)
    if path:
        return path

    # 4. Common locations
    common_paths = [
        f"/Applications/Wireshark.app/Contents/MacOS/{name}",
        f"/Applications/Zeek.app/Contents/MacOS/{name}",
        f"/opt/zeek/bin/{name}",
        f"/usr/local/zeek/bin/{name}",
        f"/opt/homebrew/bin/{name}",
        f"/opt/local/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
    ]
    for p in common_paths:
        if Path(p).is_file():
            return p

    return None
