from __future__ import annotations

import subprocess
from typing import Any, Dict, Tuple

from app.pipeline.state import PhaseHandle
from app.utils.common import find_bin, uniq_sorted
from app.utils.logger import log_runtime_error


def parse_pcap_pyshark(
    pcap_path: str,
    limit_packets: int | None,
    phase: PhaseHandle | None,
    total_packets: int | None,
    progress_every: int = 2000,
) -> Dict[str, Any]:
    tshark_path = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark_path:
        log_runtime_error("Tshark binary not found. Analysis may fail.")
        return {
            "flows": [],
            "artifacts": {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "ja3": set()},
        }

    # Fields to extract
    # 1: frame.time_epoch
    # 2: ip.src
    # 3: ip.dst
    # 4: ipv6.src
    # 5: ipv6.dst
    # 6: tcp.srcport
    # 7: tcp.dstport
    # 8: udp.srcport
    # 9: udp.dstport
    # 10: frame.protocols
    cmd = [
        tshark_path,
        "-r",
        pcap_path,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "frame.protocols",
    ]

    out = {"flows": [], "artifacts": {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "ja3": set()}}
    flow_index: Dict[Tuple[str, str, str, str, str], int] = {}
    n = 0

    try:
        # Use Popen to stream output line by line
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1) as proc:
            for line in proc.stdout:
                if phase and phase.should_skip():
                    proc.terminate()
                    break

                n += 1
                if limit_packets and n > limit_packets:
                    proc.terminate()
                    break

                if phase and (n % progress_every == 0):
                    if total_packets:
                        frac = min(n / total_packets, 1.0)
                        phase.set(int(frac * 100), f"Parsing {n:,}/{total_packets:,} packets…")
                    else:
                        phase.set(0, f"Parsing {n:,} packets…")

                parts = line.strip().split("\t")
                if len(parts) < 10:
                    continue

                # Unpack fields (tshark returns empty string for missing fields)
                # Note: tshark might return multiple values comma-separated if multiple layers match.
                # We take the first one usually.
                ts_str = parts[0]
                ip_src = parts[1]
                ip_dst = parts[2]
                ipv6_src = parts[3]
                ipv6_dst = parts[4]
                tcp_sport = parts[5]
                tcp_dport = parts[6]
                udp_sport = parts[7]
                udp_dport = parts[8]
                protos = parts[9]

                ts = float(ts_str) if ts_str else 0.0

                # Determine src/dst/proto
                src = ip_src or ipv6_src
                dst = ip_dst or ipv6_dst

                # Handle comma-separated values (e.g. tunneled traffic) - take first
                if "," in src:
                    src = src.split(",")[0]
                if "," in dst:
                    dst = dst.split(",")[0]

                if not src or not dst:
                    continue

                # Ports
                sport = tcp_sport or udp_sport
                dport = tcp_dport or udp_dport
                if "," in sport:
                    sport = sport.split(",")[0]
                if "," in dport:
                    dport = dport.split(",")[0]

                # Protocol (highest layer)
                # frame.protocols is like "eth:ethertype:ip:tcp:http"
                # We want the last interesting one.
                proto_list = protos.split(":")
                proto = proto_list[-1] if proto_list else "unknown"

                key = (src, dst, str(sport), str(dport), proto)
                idx = flow_index.get(key, -1)

                if idx < 0:
                    flow = {
                        "src": src,
                        "dst": dst,
                        "sport": str(sport),
                        "dport": str(dport),
                        "proto": proto,
                        "count": 0,
                        "pkt_times": [],
                    }
                    out["flows"].append(flow)
                    idx = len(out["flows"]) - 1
                    flow_index[key] = idx

                flow = out["flows"][idx]
                flow["count"] += 1
                flow["pkt_times"].append(ts)

                out["artifacts"]["ips"].add(src)
                out["artifacts"]["ips"].add(dst)

            # Check for errors after loop
            if proc.poll() and proc.returncode != 0:
                # If we terminated early, returncode might be non-zero (SIGTERM)
                # But if we didn't terminate and it failed:
                if not (limit_packets and n >= limit_packets) and not (phase and phase.should_skip()):
                     stderr = proc.stderr.read()
                     if stderr:
                         log_runtime_error(f"Tshark failed: {stderr}")

    except Exception as e:
        log_runtime_error(f"Tshark parsing loop failed: {e}")

    if phase:
        phase.done("Tshark parsing complete." if not phase.should_skip() else "Parsing skipped.")

    out["artifacts"] = {k: uniq_sorted(v) for k, v in out["artifacts"].items()}
    return out
