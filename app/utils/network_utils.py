from __future__ import annotations

import ipaddress
import socket


def resolve_ip(ip: str) -> str | None:
    """Resolve IP to domain name (Reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_whois_info(target: str) -> dict | str:
    """
    Retrieve WHOIS information for a domain or IP.
    Returns a dictionary or string depending on the library output,
    or an error message string on failure.
    """
    import whois

    try:
        w = whois.whois(target)
        if hasattr(w, "text"):
            return w
        return dict(w)
    except Exception as e:
        return f"WHOIS lookup failed for {target}: {e}"


def is_public_ipv4(s: str) -> bool:
    """Check if string is a valid *public* IPv4 address."""
    try:
        ip = ipaddress.ip_address(s)
        return isinstance(ip, ipaddress.IPv4Address) and ip.is_global
    except (ValueError, TypeError):
        return False
