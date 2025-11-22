import json
from typing import Any, Dict

from openai import OpenAI

SYSTEM_INSTRUCTIONS = """You are an expert Security Operations Center (SOC) Analyst and Threat Hunter.
Your goal is to analyze network traffic summaries and security artifacts to detect potential threats, malware,
and anomalous behavior.
You are provided with data derived from PCAP analysis, including:
- Traffic flow statistics and volume.
- Zeek logs (connections, DNS, HTTP, SSL).
- Potential C2 beaconing candidates.
- OSINT enrichment for IPs and domains.
- Carved file metadata.

Your analysis must be:
1. **Objective**: Base findings strictly on the provided evidence.
2. **Prioritized**: Highlight critical threats first (High/Critical severity).
3. **Contextual**: Correlate different data points (e.g., a suspicious domain in DNS logs + beaconing behavior).
4. **Actionable**: Provide concrete recommendations for containment and remediation.

Avoid generic advice. Focus on specific indicators found in the data. If no significant threats are found,
state that clearly but note any interesting anomalies."""


def generate_report(base_url: str, api_key: str, model: str, context: Dict[str, Any]) -> str:
    """
    Generate an LLM report using a summarized context that always fits small context models (4k).
    """

    # --- Summaries ---
    feats = context.get("features") or {}
    osint = context.get("osint") or {}
    zeek = context.get("zeek") or {}
    beacon = context.get("beaconing") or []
    carved = context.get("carved") or []

    summary = {
        "packet_count": context.get("packet_count"),
        "flow_count": len(feats.get("flows") or []),
        "artifact_counts": {k: len(v or []) for k, v in (feats.get("artifacts") or {}).items() if isinstance(v, list)},
        "zeek_tables": {k: len(v or []) for k, v in zeek.items()},
        "osint": {
            "ip_count": len(osint.get("ips") or {}),
            "domain_count": len(osint.get("domains") or {}),
            "ja3_count": len(osint.get("ja3") or {}),
        },
        "beacon_candidates": len(beacon or []),
        "carved_files": len(carved or []),
        "config": context.get("config") or {},
    }

    # --- Highlight samples ---
    highlights = {
        "top_flows": (feats.get("flows") or [])[:5],
        "sample_zeek": {k: (rows[:3] if isinstance(rows, list) else []) for k, rows in zeek.items()},
        "sample_osint_ips": list((osint.get("ips") or {}).keys())[:10],
        "sample_osint_domains": list((osint.get("domains") or {}).keys())[:10],
        "sample_carved": carved[:5],
        "sample_beacon": beacon[:5] if isinstance(beacon, list) else [],
    }

    prompt = f"""
You are a senior SOC analyst. Based on summarized PCAP hunting results, write a concise and actionable report.

=== SUMMARY ===
{json.dumps(summary, ensure_ascii=False)}

=== HIGHLIGHTS (examples only, not full data) ===
{json.dumps(highlights, ensure_ascii=False)}

Write the report in 7 sections:
1. Executive Summary
2. Key Findings
3. Indicators & Evidence (IPs/domains/hashes, notable Zeek records)
4. OSINT Corroboration (from VT/GreyNoise/Shodan/etc.)
5. Potential Beaconing / C2 Rationale
6. Risk Assessment (Low/Med/High) and Likely Impact
7. Recommended Actions (prioritized, concrete)
    """

    client = OpenAI(base_url=base_url, api_key=api_key)

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_INSTRUCTIONS},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1200,
        temperature=0.2,
    )
    return resp.choices[0].message.content if resp and resp.choices else "_No content returned from the model._"
