from __future__ import annotations

import time
from typing import Any, Dict

from app.pipeline.state import PhaseHandle
from app.security.opsec import hardened_session
from app.utils.common import is_public_ipv4

S = hardened_session(timeout=12)


def _j(url, headers=None, params=None):
    try:
        r = S.get(url, headers=headers or {}, params=params or {})
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {"_raw": r.text}
        return {"_error": f"HTTP {r.status_code}", "_url": url}
    except Exception as e:
        return {"_error": str(e), "_url": url}


def enrich(
    artifacts: Dict[str, list], keys: Dict[str, str], phase: PhaseHandle | None = None, throttle: float = 0.35
) -> Dict[str, Any]:
    if phase and phase.should_skip():
        phase.done("OSINT skipped.")
        return {"ips": {}, "domains": {}, "ja3": {}}

    ips = [ip for ip in artifacts.get("ips", []) if is_public_ipv4(ip)]
    doms = artifacts.get("domains", [])
    total = len(ips) + len(doms)
    done = 0
    res = {"ips": {}, "domains": {}, "ja3": {}}

    def tick(msg):
        nonlocal done
        done += 1
        if phase and total > 0:
            phase.set(10 + int((done / total) * 80), msg)

    if phase:
        phase.set(5, f"Querying {len(ips)} IPs and {len(doms)} domains…")

    for ip in ips:
        if phase and phase.should_skip():
            break
        obj = {}
        if keys.get("GREYNOISE_KEY"):
            obj["greynoise"] = _j(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": keys["GREYNOISE_KEY"], "Accept": "application/json"},
            )
        if keys.get("ABUSEIPDB_KEY"):
            obj["abuseipdb"] = _j(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": keys["ABUSEIPDB_KEY"], "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
        if keys.get("VT_KEY"):
            obj["vt"] = _j(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": keys["VT_KEY"]})
        if keys.get("SHODAN_KEY"):
            obj["shodan"] = _j(f"https://api.shodan.io/shodan/host/{ip}", params={"key": keys["SHODAN_KEY"]})
        res["ips"][ip] = obj
        tick(f"OSINT IP {ip}")
        time.sleep(throttle)

    for dom in doms:
        if phase and phase.should_skip():
            break
        obj = {}
        if keys.get("VT_KEY"):
            obj["vt"] = _j(f"https://www.virustotal.com/api/v3/domains/{dom}", headers={"x-apikey": keys["VT_KEY"]})
        if keys.get("OTX_KEY"):
            obj["otx"] = _j(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{dom}/general",
                headers={"X-OTX-API-KEY": keys["OTX_KEY"]},
            )
        res["domains"][dom] = obj
        tick(f"OSINT domain {dom}")
        time.sleep(throttle)

    if phase:
        phase.done("OSINT enrichment complete." if not phase.should_skip() else "OSINT skipped.")
    return res
