from __future__ import annotations

import subprocess


def count_packets_fast(pcap_path: str) -> int | None:
    try:
        proc = subprocess.run(
            ["sh", "-lc", f'tshark -r "{pcap_path}" -T fields -e frame.number 2>/dev/null | wc -l'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        total = int(proc.stdout.strip() or "0")
        return total if total > 0 else None
    except Exception:
        return None
