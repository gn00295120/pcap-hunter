from __future__ import annotations

import hashlib
import pathlib


def sha256_bytes(b: bytes) -> str:
    """Calculate SHA256 hash of bytes."""
    return hashlib.sha256(b).hexdigest()


def ensure_dir(p: pathlib.Path) -> None:
    """Ensure directory exists, creating if necessary."""
    p.mkdir(parents=True, exist_ok=True)
