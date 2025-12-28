from __future__ import annotations

from typing import Any, Iterable


def uniq_sorted(seq: Iterable[Any] | None) -> list[Any]:
    """Return sorted unique non-empty values from sequence."""
    if seq is None:
        return []
    return sorted(list({x for x in seq if x}))


def make_slug(title: str) -> str:
    """Convert title into a safe slug (for session keys)."""
    return "".join(c.lower() if c.isalnum() else "_" for c in title)
