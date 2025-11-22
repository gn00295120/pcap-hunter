from __future__ import annotations

from typing import Any, Dict, List

import numpy as np
import pandas as pd


def periodicity_score(ts: List[float]) -> Dict[str, Any]:
    if not ts or len(ts) < 6:
        return {"count": len(ts), "mean_gap": None, "std_gap": None, "cv": None, "entropy": None, "score": 0.0}
    ts = sorted(ts)
    gaps = np.diff(ts)
    if len(gaps) == 0:
        return {
            "count": len(ts),
            "mean_gap": 0,
            "std_gap": 0,
            "cv": 0,
            "entropy": 0,
            "score": 0.0
        }
    mean_gap = float(np.mean(gaps))
    std_gap = float(np.std(gaps))
    cv = float(std_gap / mean_gap) if mean_gap > 0 else None
    bins = np.histogram(gaps, bins=min(20, max(5, int(len(gaps)/3))))[0]
    probs = bins / bins.sum() if bins.sum() > 0 else np.array([1.0])
    entropy = float(-np.sum([p*np.log2(p) for p in probs if p > 0]))
    score = (1.0 - min(cv or 1.0, 1.0)) * 0.6 + (1.0 - min(entropy/4.0, 1.0)) * 0.4
    score *= min(len(ts)/50.0, 1.0)
    return {
        "count": len(ts),
        "mean_gap": mean_gap,
        "std_gap": std_gap,
        "cv": cv,
        "entropy": entropy,
        "score": float(score)
    }

def rank_beaconing(flows: List[Dict[str, Any]], top_n=20) -> pd.DataFrame:
    rows = []
    for f in flows:
        stats = periodicity_score(f.get("pkt_times", []))
        rows.append({
            "src": f.get("src"), "dst": f.get("dst"),
            "sport": f.get("sport"), "dport": f.get("dport"),
            "proto": f.get("proto"), "pkts": stats["count"],
            "mean_gap": stats["mean_gap"], "std_gap": stats["std_gap"],
            "cv": stats["cv"], "entropy": stats["entropy"], "score": stats["score"]
        })
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values("score", ascending=False).head(top_n).reset_index(drop=True)
