from __future__ import annotations

import hashlib
import ipaddress
import pathlib


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


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
