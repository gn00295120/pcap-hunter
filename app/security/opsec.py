from __future__ import annotations

import requests


def hardened_session(timeout=15):
    s = requests.Session()
    s.headers.update({"User-Agent": "pcap-hunter/1.0"})
    s.verify = True
    # No redirects across schemes
    s.max_redirects = 3
    s.trust_env = False  # ignore system proxies by default
    s.request = _wrap_request(s.request, timeout=timeout)
    return s

def _wrap_request(fn, timeout=15):
    def _inner(method, url, **kwargs):
        kwargs.setdefault("timeout", timeout)
        return fn(method, url, **kwargs)
    return _inner

def redact(text: str, keep=3) -> str:
    if not text:
        return text
    if len(text) <= keep:
        return "***"
    return text[:keep] + "…"
