from __future__ import annotations

import hashlib
import ipaddress
import pathlib
import socket


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def resolve_ip(ip: str) -> str | None:
    """Resolve IP to domain name (Reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_whois_info(target: str) -> dict | str:
    """
    Retrieve WHOIS information for a domain or IP.
    Returns a dictionary or string depending on the library output,
    or an error message string on failure.
    """
    import whois

    try:
        # whois.whois supports both domains and IPs
        w = whois.whois(target)

        # Convert to dict if it's a specific object
        if hasattr(w, "text"):
            return w
        return dict(w)
    except Exception as e:
        # Fallback: sometimes it fails for IPs, we can try to return a partial object or just the error
        return f"WHOIS lookup failed for {target}: {e}"


def filter_flows_by_ips(flows: list[dict], selected_ips: set[str]) -> list[dict]:
    """
    Return a list of flows where src or dst is in selected_ips.
    If selected_ips is empty, return all flows.
    """
    if not selected_ips:
        return flows
    return [f for f in flows if f.get("src") in selected_ips or f.get("dst") in selected_ips]


def uniq_sorted(seq):
    if seq is None:
        return []
    return sorted(list({x for x in seq if x}))


def ensure_dir(p: pathlib.Path):
    p.mkdir(parents=True, exist_ok=True)


def make_slug(title: str) -> str:
    """Convert title into a safe slug (for session keys)."""
    return "".join(c.lower() if c.isalnum() else "_" for c in title)


def is_public_ipv4(s: str) -> bool:
    """Check if string is a valid *public* IPv4 address."""
    try:
        ip = ipaddress.ip_address(s)
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except Exception:
        return False


def find_bin(name: str, env_key: str = "", cfg_key: str = "") -> str | None:
    """
    Find a binary by name, checking:
    1. Streamlit session state config (if cfg_key provided)
    2. Environment variable (if env_key provided)
    3. PATH
    4. Common macOS locations
    """
    import os
    import shutil
    from pathlib import Path

    # 1. Config
    if cfg_key:
        try:
            import streamlit as st

            val = st.session_state.get(cfg_key)
            if val and Path(val).exists():
                return val
        except ImportError:
            pass

    # 2. Env var
    if env_key:
        val = os.environ.get(env_key)
        if val and Path(val).exists():
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
        if Path(p).exists():
            return p

    return None
