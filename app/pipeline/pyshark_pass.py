from __future__ import annotations

from typing import Any, Dict, Tuple

import pyshark

from app.pipeline.state import PhaseHandle
from app.utils.common import find_bin, uniq_sorted


def parse_pcap_pyshark(
    pcap_path: str,
    limit_packets: int | None,
    phase: PhaseHandle | None,
    total_packets: int | None,
    progress_every: int = 500,
) -> Dict[str, Any]:
    tshark_path = find_bin("tshark", cfg_key="cfg_tshark_bin")
    cap = pyshark.FileCapture(pcap_path, keep_packets=False, tshark_path=tshark_path)
    out = {"flows": [], "artifacts": {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "ja3": set()}}
    flow_index: Dict[Tuple[str, str, str, str, str], int] = {}
    n = 0

    for pkt in cap:
        if phase and phase.should_skip():
            break
        n += 1
        if limit_packets and n > limit_packets:
            break

        if phase and (n % progress_every == 0):
            if total_packets:
                frac = min(n / total_packets, 1.0)
                phase.set(int(frac * 100), f"Parsing {n:,}/{total_packets:,} packets…")
            else:
                # Indeterminate progress: keep bar at 0 but update text
                phase.set(0, f"Parsing {n:,} packets…")

        try:
            l3 = "ipv6" if hasattr(pkt, "ipv6") else ("ip" if hasattr(pkt, "ip") else None)
            if not l3:
                continue
            ts = float(getattr(pkt.frame_info, "time_epoch", "0") or "0")
            src = getattr(getattr(pkt, l3), "src", None)
            dst = getattr(getattr(pkt, l3), "dst", None)
            proto = pkt.highest_layer
            sp = (
                getattr(pkt, "udp", None)
                and getattr(pkt.udp, "srcport", None)
                or getattr(pkt, "tcp", None)
                and getattr(pkt.tcp, "srcport", None)
            )
            dp = (
                getattr(pkt, "udp", None)
                and getattr(pkt.udp, "dstport", None)
                or getattr(pkt, "tcp", None)
                and getattr(pkt.tcp, "dstport", None)
            )
            key = (src, dst, str(sp), str(dp), proto)
            idx = flow_index.get(key, -1)
            if idx < 0:
                flow = {
                    "src": src,
                    "dst": dst,
                    "sport": str(sp),
                    "dport": str(dp),
                    "proto": proto,
                    "count": 0,
                    "dns": [],
                    "http": [],
                    "tls": [],
                    "smb": [],
                    "pkt_times": [],
                }
                out["flows"].append(flow)
                idx = len(out["flows"]) - 1
                flow_index[key] = idx
            flow = out["flows"][idx]
            flow["count"] += 1
            flow["pkt_times"].append(ts)
            if src:
                out["artifacts"]["ips"].add(src)
            if dst:
                out["artifacts"]["ips"].add(dst)
        except Exception:
            continue

    if phase:
        phase.done("PyShark parsing complete." if not phase.should_skip() else "PyShark skipped.")
    out["artifacts"] = {k: uniq_sorted(v) for k, v in out["artifacts"].items()}
    return out
