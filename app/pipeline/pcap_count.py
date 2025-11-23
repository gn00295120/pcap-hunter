from __future__ import annotations

import subprocess

from app.utils.common import find_bin


def count_packets_fast(pcap_path: str) -> int | None:
    # Try capinfos first (fastest)
    capinfos = find_bin("capinfos")
    if capinfos:
        try:
            # -T: Table output, -r: Headerless, -c: Count
            proc = subprocess.run(
                [capinfos, "-T", "-r", "-c", pcap_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            val = proc.stdout.strip()
            if val.isdigit():
                return int(val)
        except Exception:
            pass

    # Fallback to tshark
    tshark = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if tshark:
        try:
            # tshark -r file -T fields -e frame.number | wc -l
            # We'll just count lines in python to avoid shell pipe issues
            proc = subprocess.run(
                [tshark, "-r", pcap_path, "-T", "fields", "-e", "frame.number"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            return len(proc.stdout.splitlines())
        except Exception:
            pass

    return None
