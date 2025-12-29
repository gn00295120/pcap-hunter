import json
from typing import Any, Dict, List

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


def generate_report(
    base_url: str, api_key: str, model: str, context: Dict[str, Any], language: str = "US English"
) -> str:
    """
    Generate an LLM report using a summarized context.
    """

    # --- Summaries ---
    feats = context.get("features") or {}
    osint = context.get("osint") or {}
    zeek = context.get("zeek") or {}
    beacon = context.get("beaconing") or []
    carved = context.get("carved") or []

    # Calculate protocol distribution for summary
    flows = feats.get("flows") or []
    proto_counts = {}
    for f in flows:
        p = f.get("proto", "Unknown")
        proto_counts[p] = proto_counts.get(p, 0) + 1
    top_protos = dict(sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:5])

    summary = {
        "packet_count": context.get("packet_count"),
        "flow_count": len(flows),
        "top_protocols": top_protos,
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
        "top_flows": flows[:5],
        "sample_zeek": {k: (rows[:3] if isinstance(rows, list) else []) for k, rows in zeek.items()},
        "sample_osint_ips": list((osint.get("ips") or {}).keys())[:10],
        "sample_osint_domains": list((osint.get("domains") or {}).keys())[:10],
        "sample_carved": carved[:5],
        "sample_beacon": beacon[:5] if isinstance(beacon, list) else [],
    }

    # Language instruction logic
    lang_instruction = ""
    if language == "Tradition Chinese (zh-tw)":
        lang_instruction = "IMPORTANT: You MUST write the entire report in Traditional Chinese (using Taiwan usage/wording/vocabulary)."
    elif language == "Simplified Chinese (zh-cn)":
        lang_instruction = "IMPORTANT: You MUST write the entire report in Simplified Chinese (using Mainland China usage/wording/vocabulary)."
    elif language != "US English":
        lang_instruction = f"IMPORTANT: You MUST write the entire report in {language}."

    # Define sections to generate separately
    sections = [
        ("Executive Summary", "Write the 'Executive Summary' section. Focus on high-level impact and critical findings."),
        ("Key Findings", "Write the 'Key Findings' section. List the most important observations."),
        ("Indicators & Evidence", "Write the 'Indicators & Evidence' section. Include IPs, domains, hashes, and notable Zeek records."),
        ("OSINT Corroboration", "Write the 'OSINT Corroboration' section. Cite data from VT/GreyNoise/Shodan if available."),
        ("Potential Beaconing / C2 Rationale", "Write the 'Potential Beaconing / C2 Rationale' section. Explain detailed reasoning for suspect flows."),
        ("Risk Assessment", "Write the 'Risk Assessment (Low/Med/High) and Likely Impact' section."),
        ("Recommended Actions", "Write the 'Recommended Actions' section. Provide a concise, prioritized list of the top 5-7 concrete steps."),
    ]

    # Translate section titles if not English
    translations = {
        "Tradition Chinese (zh-tw)": {
            "Executive Summary": "執行摘要",
            "Key Findings": "主要發現",
            "Indicators & Evidence": "指標與證據",
            "OSINT Corroboration": "OSINT 偵察驗證",
            "Potential Beaconing / C2 Rationale": "潛在信標 / C2 原理說明",
            "Risk Assessment": "風險評估",
            "Recommended Actions": "建議處置行動",
        },
        "Simplified Chinese (zh-cn)": {
            "Executive Summary": "执行摘要",
            "Key Findings": "主要发现",
            "Indicators & Evidence": "指标与证据",
            "OSINT Corroboration": "OSINT 侦察验证",
            "Potential Beaconing / C2 Rationale": "潜在信标 / C2 原理说明",
            "Risk Assessment": "风险评估",
            "Recommended Actions": "建议处置行动",
        },
        "Japanese": {
            "Executive Summary": "エグゼクティブサマリー",
            "Key Findings": "主な発見事項",
            "Indicators & Evidence": "指標と証拠",
            "OSINT Corroboration": "OSINTによる裏付け",
            "Potential Beaconing / C2 Rationale": "潜在的なビーコニング / C2の根拠",
            "Risk Assessment": "リスク評価",
            "Recommended Actions": "推奨されるアクション",
        },
        "Korean": {
            "Executive Summary": "요약 보고서",
            "Key Findings": "주요 결과",
            "Indicators & Evidence": "지표 및 증거",
            "OSINT Corroboration": "OSINT 교차 검증",
            "Potential Beaconing / C2 Rationale": "잠재적 비코닝 / C2 근거",
            "Risk Assessment": "위험 평가",
            "Recommended Actions": "권장 조치 사항",
        },
        "Italian": {
            "Executive Summary": "Riepilogo Esecutivo",
            "Key Findings": "Risultati Principali",
            "Indicators & Evidence": "Indicatori ed Evidenze",
            "OSINT Corroboration": "Corroborazione OSINT",
            "Potential Beaconing / C2 Rationale": "Potenziale Beaconing / Analisi C2",
            "Risk Assessment": "Valutazione del Rischio",
            "Recommended Actions": "Azioni Raccomandate",
        },
        "Spanish": {
            "Executive Summary": "Resumen Ejecutivo",
            "Key Findings": "Hallazgos Clave",
            "Indicators & Evidence": "Indicadores y Evidencias",
            "OSINT Corroboration": "Corroboración OSINT",
            "Potential Beaconing / C2 Rationale": "Posible Beaconing / Razón de C2",
            "Risk Assessment": "Evaluación de Riesgos",
            "Recommended Actions": "Acciones Recomendadas",
        },
        "French": {
            "Executive Summary": "Résumé Exécutif",
            "Key Findings": "Principales Constatations",
            "Indicators & Evidence": "Indicateurs et Preuves",
            "OSINT Corroboration": "Corroboration OSINT",
            "Potential Beaconing / C2 Rationale": "Beaconing Potentiel / Analyse C2",
            "Risk Assessment": "Évaluation des Risques",
            "Recommended Actions": "Actions Recommandées",
        },
        "German": {
            "Executive Summary": "Zusammenfassung für die Geschäftsführung",
            "Key Findings": "Wichtigste Erkenntnisse",
            "Indicators & Evidence": "Indikatoren und Beweise",
            "OSINT Corroboration": "OSINT-Bestätigung",
            "Potential Beaconing / C2 Rationale": "Potenzielles Beaconing / C2-Begründung",
            "Risk Assessment": "Risikobewertung",
            "Recommended Actions": "Empfohlene Maßnahmen",
        }
    }

    t_map = translations.get(language, {})

    client = OpenAI(base_url=base_url, api_key=api_key)
    
    # Common system message
    msg_system = SYSTEM_INSTRUCTIONS
    if lang_instruction:
        msg_system += f"\n\n{lang_instruction}"
    
    full_report_parts = []
    
    for title, instruction in sections:
        # Translate title and instructions if possible
        display_title = t_map.get(title, title)
        
        # Construct prompt for this specific section
        section_prompt = f"""
{lang_instruction}

You are a senior SOC analyst. Based on summarized PCAP hunting results, write ONLY the following section of the report:

**{display_title}**

Instruction: {instruction} (WRITE IN {language.upper()})

=== SUMMARY ===
{json.dumps(summary, ensure_ascii=False)}

=== HIGHLIGHTS (examples only, not full data) ===
{json.dumps(highlights, ensure_ascii=False)}
"""
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": msg_system},
                    {"role": "user", "content": section_prompt},
                ],
                max_tokens=2000, # Per section
                temperature=0.2,
            )
            content = resp.choices[0].message.content if resp and resp.choices else ""
            if content:
                # Add a translated header for the section
                full_report_parts.append(f"## {display_title}\n\n{content}")
        except Exception as e:
            full_report_parts.append(f"## {display_title}\n\n_Error generating section: {str(e)}_")

    if not full_report_parts:
        return "_No content returned from the model._"

    return "\n\n".join(full_report_parts)


def test_connection(base_url: str, api_key: str, model: str) -> str:
    """
    Test connectivity to the LLM endpoint by performing a minimal API call.
    Returns an empty string on success, or an error message on failure.
    """
    if not base_url:
        return "Missing Base URL."

    try:
        client = OpenAI(base_url=base_url, api_key=api_key or "lm-studio")
        client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
        return ""
    except Exception as e:
        return str(e)


def fetch_models(base_url: str, api_key: str) -> List[str]:
    """
    Fetch available models from the LLM endpoint.
    Returns a list of model IDs. Returns an empty list on failure.
    """
    if not base_url:
        return []

    try:
        client = OpenAI(base_url=base_url, api_key=api_key or "lm-studio")
        models = client.models.list()
        return [m.id for m in models]
    except Exception:
        return []
