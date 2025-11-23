from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from pathlib import Path

import pandas as pd

from app.pipeline.state import PhaseHandle
from app.utils.common import ensure_dir


def _find_bin(name: str) -> str | None:
    # Check session state config first
    if name == "zeek":
        import streamlit as st

        cfg_bin = st.session_state.get("cfg_zeek_bin")
        if cfg_bin and Path(cfg_bin).exists():
            return cfg_bin

    # Check env var first
    if name == "zeek" and os.environ.get("ZEEK_BIN"):
        return os.environ["ZEEK_BIN"]

    # Check PATH
    path = shutil.which(name)
    if path:
        return path

    # Check common locations
    common_paths = [
        f"/opt/zeek/bin/{name}",
        f"/usr/local/zeek/bin/{name}",
        f"/opt/homebrew/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/Applications/Zeek.app/Contents/MacOS/{name}",
    ]
    for p in common_paths:
        if Path(p).exists():
            return p
    return None


def run_zeek(pcap_path: str, out_dir: str, phase: PhaseHandle | None = None) -> dict[str, str]:
    ensure_dir(out_dir)
    zeek_bin = _find_bin("zeek")
    if not zeek_bin:
        raise FileNotFoundError("Zeek binary not found. Please install Zeek or set ZEEK_BIN env var.")

    if phase and phase.should_skip():
        phase.done("Zeek skipped.")
        return {}

    cmd_json = [zeek_bin, "-C", "-r", pcap_path, "policy/tuning/json-logs.zeek"]
    cmd_ascii = [zeek_bin, "-C", "-r", pcap_path]

    if phase:
        phase.set(5, "Launching Zeek (JSON logs)…")
    try:
        subprocess.run(cmd_json, cwd=out_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if phase:
            phase.set(60, "Zeek (JSON) completed, collecting logs…")
    except subprocess.CalledProcessError:
        if phase:
            phase.set(20, "Retrying Zeek with ASCII logs…")
        subprocess.run(cmd_ascii, cwd=out_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if phase:
            phase.set(60, "Zeek (ASCII) completed, collecting logs…")

    logs = {}
    for name in ("conn.log", "dns.log", "http.log", "ssl.log"):
        p = pathlib.Path(out_dir) / name
        if p.exists():
            logs[name] = str(p)
    if phase:
        phase.done("Zeek processing complete.")
    return logs


def _load_json_lines(path: str) -> pd.DataFrame | None:
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if s and not s.startswith("#"):
                lines.append(json.loads(s))
    return pd.DataFrame(lines) if lines else None


def _load_ascii(path: str) -> pd.DataFrame:
    cols = None
    records = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            if not ln.strip():
                continue
            if ln.startswith("#fields"):
                cols = ln.strip().split("\t")[1:]
                continue
            if ln.startswith("#"):
                continue
            parts = ln.rstrip("\n").split("\t")
            if cols and len(parts) == len(cols):
                records.append(dict(zip(cols, parts)))
    return pd.DataFrame(records)


def load_zeek_any(path: str) -> pd.DataFrame:
    try:
        df = _load_json_lines(path)
        if df is not None:
            return df
    except Exception:
        pass
    return _load_ascii(path)
