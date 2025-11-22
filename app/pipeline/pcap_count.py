from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _find_bin(name: str) -> str | None:
    # Check PATH first
    path = shutil.which(name)
    if path:
        return path
    # Check standard macOS Wireshark location
    mac_path = Path(f"/Applications/Wireshark.app/Contents/MacOS/{name}")
    if mac_path.exists():
        return str(mac_path)
    return None


def count_packets_fast(pcap_path: str) -> int | None:
    # Try capinfos first (fastest)
    capinfos = _find_bin("capinfos")
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
    tshark = _find_bin("tshark")
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
