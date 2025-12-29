"""SSL/TLS Certificate extraction and analysis.

Extracts X.509 certificates from PCAP files and analyzes them for:
- Certificate validity
- Self-signed detection
- Expired/not-yet-valid certificates
- Suspicious certificate patterns
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from app.pipeline.state import PhaseHandle
from app.utils.common import find_bin

logger = logging.getLogger(__name__)


@dataclass
class Certificate:
    """Parsed X.509 certificate data."""

    # Core fields
    serial: str
    subject_cn: str
    subject_o: str
    issuer_cn: str
    issuer_o: str
    not_before: datetime | None
    not_after: datetime | None
    fingerprint_sha256: str
    fingerprint_sha1: str

    # Extended fields
    sans: list[str] = field(default_factory=list)
    key_type: str = ""
    key_bits: int = 0
    signature_algorithm: str = ""
    version: int = 3

    # Analysis results
    is_self_signed: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    days_until_expiry: int | None = None
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)

    # Connection info
    server_name: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0


def parse_datetime(dt_str: str) -> datetime | None:
    """Parse various datetime formats from certificate fields."""
    if not dt_str or dt_str == "-":
        return None

    # Common formats from tshark
    formats = [
        "%b %d %H:%M:%S %Y GMT",
        "%Y-%m-%d %H:%M:%S",
        "%Y%m%d%H%M%SZ",
        "%b %d %H:%M:%S %Y",
    ]

    dt_str = dt_str.strip()
    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    logger.debug(f"Failed to parse datetime: {dt_str}")
    return None


def extract_certificates_tshark(pcap_path: str | Path, phase: PhaseHandle | None = None) -> list[Certificate]:
    """
    Extract certificates from PCAP using tshark.

    Args:
        pcap_path: Path to PCAP file
        phase: PhaseHandle for progress updates

    Returns:
        List of Certificate objects
    """
    tshark = find_bin("tshark", cfg_key="cfg_tshark_bin")
    if not tshark:
        logger.error("tshark not found")
        return []

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        logger.error(f"PCAP file not found: {pcap_path}")
        return []

    if phase:
        phase.set(10, "Extracting TLS certificates...")

    # Fields to extract
    fields = [
        "frame.number",
        "ip.src",
        "ip.dst",
        "tcp.dstport",
        "tls.handshake.certificate",
        "tls.handshake.extensions_server_name",
        "x509sat.uTF8String",
        "x509sat.printableString",
        "x509ce.dNSName",
        "x509af.utcTime",
        "x509af.generalizedTime",
        "x509af.serialNumber",
        "x509af.algorithm.id",
    ]

    field_args = []
    for f in fields:
        field_args.extend(["-e", f])

    cmd = [
        tshark,
        "-r",
        str(pcap_path),
        "-Y",
        "tls.handshake.certificate",
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        *field_args,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.warning(f"tshark returned {result.returncode}: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("tshark timed out during certificate extraction")
        return []
    except Exception as e:
        logger.error(f"Failed to run tshark: {e}")
        return []

    certificates = []
    lines = result.stdout.strip().split("\n")

    for i, line in enumerate(lines):
        if not line.strip():
            continue

        if phase and i % 10 == 0:
            pct = 10 + int((i / len(lines)) * 60)
            phase.set(pct, f"Processing certificate {i + 1}/{len(lines)}...")

        try:
            parts = line.split("|")
            if len(parts) < 5:
                continue

            frame_num = parts[0] if len(parts) > 0 else ""
            src_ip = parts[1] if len(parts) > 1 else ""
            dst_ip = parts[2] if len(parts) > 2 else ""
            dst_port = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
            cert_hex = parts[4] if len(parts) > 4 else ""
            server_name = parts[5] if len(parts) > 5 else ""

            if not cert_hex:
                continue

            # Parse certificate data (hex encoded)
            cert_bytes = bytes.fromhex(cert_hex.replace(":", "").replace(" ", ""))

            # Calculate fingerprints
            sha256_fp = hashlib.sha256(cert_bytes).hexdigest()
            sha1_fp = hashlib.sha1(cert_bytes).hexdigest()

            # Extract certificate details using openssl (more reliable than tshark fields)
            cert_info = _parse_cert_with_openssl(cert_bytes)

            cert = Certificate(
                serial=cert_info.get("serial", ""),
                subject_cn=cert_info.get("subject_cn", ""),
                subject_o=cert_info.get("subject_o", ""),
                issuer_cn=cert_info.get("issuer_cn", ""),
                issuer_o=cert_info.get("issuer_o", ""),
                not_before=cert_info.get("not_before"),
                not_after=cert_info.get("not_after"),
                fingerprint_sha256=sha256_fp,
                fingerprint_sha1=sha1_fp,
                sans=cert_info.get("sans", []),
                key_type=cert_info.get("key_type", ""),
                key_bits=cert_info.get("key_bits", 0),
                signature_algorithm=cert_info.get("sig_alg", ""),
                server_name=server_name,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

            # Analyze certificate
            _analyze_certificate(cert)
            certificates.append(cert)

        except Exception as e:
            logger.debug(f"Failed to parse certificate line: {e}")
            continue

    if phase:
        phase.set(80, f"Found {len(certificates)} certificates")

    return certificates


def _parse_cert_with_openssl(cert_der: bytes) -> dict[str, Any]:
    """
    Parse certificate details using openssl.

    Args:
        cert_der: DER-encoded certificate bytes

    Returns:
        Dictionary with parsed certificate fields
    """
    result: dict[str, Any] = {}

    try:
        # Try using openssl to parse
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
            input=cert_der,
            capture_output=True,
            timeout=10,
        )

        if proc.returncode != 0:
            return result

        text = proc.stdout.decode("utf-8", errors="ignore")

        # Parse Subject
        subject_match = re.search(r"Subject: (.+)", text)
        if subject_match:
            subject = subject_match.group(1)
            cn_match = re.search(r"CN\s*=\s*([^,/]+)", subject)
            o_match = re.search(r"O\s*=\s*([^,/]+)", subject)
            result["subject_cn"] = cn_match.group(1).strip() if cn_match else ""
            result["subject_o"] = o_match.group(1).strip() if o_match else ""

        # Parse Issuer
        issuer_match = re.search(r"Issuer: (.+)", text)
        if issuer_match:
            issuer = issuer_match.group(1)
            cn_match = re.search(r"CN\s*=\s*([^,/]+)", issuer)
            o_match = re.search(r"O\s*=\s*([^,/]+)", issuer)
            result["issuer_cn"] = cn_match.group(1).strip() if cn_match else ""
            result["issuer_o"] = o_match.group(1).strip() if o_match else ""

        # Parse Serial
        serial_match = re.search(r"Serial Number:\s*\n?\s*([0-9a-fA-F:]+)", text)
        if serial_match:
            result["serial"] = serial_match.group(1).replace(":", "").lower()

        # Parse Validity
        not_before_match = re.search(r"Not Before:\s*(.+)", text)
        not_after_match = re.search(r"Not After\s*:\s*(.+)", text)
        if not_before_match:
            result["not_before"] = parse_datetime(not_before_match.group(1))
        if not_after_match:
            result["not_after"] = parse_datetime(not_after_match.group(1))

        # Parse Key info
        key_match = re.search(r"Public Key Algorithm:\s*(\w+)", text)
        if key_match:
            result["key_type"] = key_match.group(1)

        bits_match = re.search(r"(?:Public-Key|RSA Public-Key):\s*\((\d+) bit\)", text)
        if bits_match:
            result["key_bits"] = int(bits_match.group(1))

        # Parse Signature Algorithm
        sig_match = re.search(r"Signature Algorithm:\s*(\S+)", text)
        if sig_match:
            result["sig_alg"] = sig_match.group(1)

        # Parse SANs
        san_match = re.search(r"Subject Alternative Name:\s*\n(.+?)(?:\n\s*\n|\Z)", text, re.DOTALL)
        if san_match:
            san_text = san_match.group(1)
            dns_names = re.findall(r"DNS:([^,\s]+)", san_text)
            result["sans"] = dns_names

    except Exception as e:
        logger.debug(f"OpenSSL parsing failed: {e}")

    return result


def _analyze_certificate(cert: Certificate) -> None:
    """
    Analyze certificate for security issues.

    Updates cert.risk_score and cert.risk_reasons in place.
    """
    now = datetime.now(timezone.utc)
    reasons = []
    score = 0.0

    # Check self-signed
    if cert.subject_cn and cert.issuer_cn:
        if cert.subject_cn.lower() == cert.issuer_cn.lower():
            cert.is_self_signed = True
            score += 0.3
            reasons.append("self-signed")
    elif cert.subject_o and cert.issuer_o:
        if cert.subject_o.lower() == cert.issuer_o.lower():
            cert.is_self_signed = True
            score += 0.3
            reasons.append("self-signed")

    # Check validity period
    if cert.not_after:
        if cert.not_after < now:
            cert.is_expired = True
            score += 0.4
            reasons.append("expired")
        else:
            cert.days_until_expiry = (cert.not_after - now).days
            if cert.days_until_expiry < 30:
                score += 0.1
                reasons.append(f"expires in {cert.days_until_expiry} days")

    if cert.not_before and cert.not_before > now:
        cert.is_not_yet_valid = True
        score += 0.4
        reasons.append("not yet valid")

    # Check validity duration (very long = suspicious)
    if cert.not_before and cert.not_after:
        duration = (cert.not_after - cert.not_before).days
        if duration > 3650:  # > 10 years
            score += 0.2
            reasons.append(f"unusually long validity ({duration} days)")

    # Check weak key
    if cert.key_bits > 0:
        if cert.key_type.lower() == "rsa" and cert.key_bits < 2048:
            score += 0.3
            reasons.append(f"weak {cert.key_type} key ({cert.key_bits} bits)")
        elif cert.key_type.lower() in ("ec", "ecdsa") and cert.key_bits < 256:
            score += 0.3
            reasons.append(f"weak {cert.key_type} key ({cert.key_bits} bits)")

    # Check weak signature algorithm
    weak_sigs = ["md5", "sha1"]
    if cert.signature_algorithm and any(weak in cert.signature_algorithm.lower() for weak in weak_sigs):
        score += 0.2
        reasons.append(f"weak signature ({cert.signature_algorithm})")

    # Check suspicious CN patterns
    if cert.subject_cn:
        cn_lower = cert.subject_cn.lower()
        # IP address as CN
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cn_lower):
            score += 0.1
            reasons.append("IP address as CN")
        # Wildcard without domain
        if cn_lower == "*":
            score += 0.3
            reasons.append("wildcard-only CN")
        # Common malware patterns
        suspicious_patterns = ["localhost", "test", "example", "selfsigned", "dummy"]
        if any(p in cn_lower for p in suspicious_patterns):
            score += 0.2
            reasons.append("suspicious CN pattern")

    cert.risk_score = min(score, 1.0)
    cert.risk_reasons = reasons


def extract_from_zeek_ssl(zeek_tables: dict[str, pd.DataFrame]) -> list[dict[str, Any]]:
    """
    Extract certificate info from Zeek ssl.log.

    This provides less detail than full extraction but is faster.

    Args:
        zeek_tables: Dictionary of Zeek log DataFrames

    Returns:
        List of certificate summary dicts
    """
    ssl_df = zeek_tables.get("ssl.log")
    if ssl_df is None or ssl_df.empty:
        return []

    certs = []
    for _, row in ssl_df.iterrows():
        try:
            cert = {
                "src": str(row.get("id.orig_h", row.get("id_orig_h", ""))),
                "dst": str(row.get("id.resp_h", row.get("id_resp_h", ""))),
                "port": int(row.get("id.resp_p", row.get("id_resp_p", 0))),
                "server_name": str(row.get("server_name", "")),
                "subject": str(row.get("subject", "")),
                "issuer": str(row.get("issuer", "")),
                "not_valid_before": str(row.get("not_valid_before", "")),
                "not_valid_after": str(row.get("not_valid_after", "")),
                "validation_status": str(row.get("validation_status", "")),
                "version": str(row.get("version", "")),
                "cipher": str(row.get("cipher", "")),
                "curve": str(row.get("curve", "")),
            }

            # Check for issues
            issues = []
            validation = cert["validation_status"]
            if validation and validation != "-":
                if "self signed" in validation.lower():
                    issues.append("self-signed")
                if "expired" in validation.lower():
                    issues.append("expired")
                if "unable to verify" in validation.lower():
                    issues.append("unverified")

            cert["issues"] = issues
            cert["has_issues"] = len(issues) > 0

            if cert["subject"] and cert["subject"] != "-":
                certs.append(cert)

        except Exception as e:
            logger.debug(f"Failed to parse SSL log row: {e}")
            continue

    return certs


def analyze_certificates(
    pcap_path: str | Path | None = None,
    zeek_tables: dict[str, pd.DataFrame] | None = None,
    phase: PhaseHandle | None = None,
) -> dict[str, Any]:
    """
    Comprehensive certificate analysis.

    Args:
        pcap_path: Path to PCAP file (for full extraction)
        zeek_tables: Zeek log tables (for quick extraction)
        phase: PhaseHandle for progress updates

    Returns:
        Dictionary with certificate analysis results
    """
    if phase and phase.should_skip():
        phase.done("Certificate analysis skipped.")
        return {"skipped": True}

    if phase:
        phase.set(5, "Starting certificate analysis...")

    # Try full extraction from PCAP first
    certificates = []
    if pcap_path:
        certificates = extract_certificates_tshark(pcap_path, phase)

    # Fall back to Zeek ssl.log if no full extraction
    zeek_certs = []
    if zeek_tables:
        if phase:
            phase.set(85, "Extracting from Zeek ssl.log...")
        zeek_certs = extract_from_zeek_ssl(zeek_tables)

    # Deduplicate by fingerprint
    seen_fingerprints = {c.fingerprint_sha256 for c in certificates}
    unique_certs = certificates

    # Build summary
    self_signed_count = sum(1 for c in unique_certs if c.is_self_signed)
    expired_count = sum(1 for c in unique_certs if c.is_expired)
    not_yet_valid_count = sum(1 for c in unique_certs if c.is_not_yet_valid)
    high_risk_count = sum(1 for c in unique_certs if c.risk_score >= 0.5)

    result = {
        "total_certificates": len(unique_certs),
        "unique_fingerprints": len(seen_fingerprints),
        "self_signed": self_signed_count,
        "expired": expired_count,
        "not_yet_valid": not_yet_valid_count,
        "high_risk": high_risk_count,
        "certificates": [
            {
                "subject_cn": c.subject_cn,
                "subject_o": c.subject_o,
                "issuer_cn": c.issuer_cn,
                "issuer_o": c.issuer_o,
                "serial": c.serial,
                "not_before": c.not_before.isoformat() if c.not_before else "",
                "not_after": c.not_after.isoformat() if c.not_after else "",
                "fingerprint_sha256": c.fingerprint_sha256,
                "fingerprint_sha1": c.fingerprint_sha1,
                "sans": c.sans[:10],  # Limit SANs
                "key_type": c.key_type,
                "key_bits": c.key_bits,
                "signature_algorithm": c.signature_algorithm,
                "server_name": c.server_name,
                "dst_ip": c.dst_ip,
                "dst_port": c.dst_port,
                "is_self_signed": c.is_self_signed,
                "is_expired": c.is_expired,
                "is_not_yet_valid": c.is_not_yet_valid,
                "days_until_expiry": c.days_until_expiry,
                "risk_score": c.risk_score,
                "risk_reasons": c.risk_reasons,
            }
            for c in unique_certs
        ],
        "zeek_ssl_summary": {
            "total": len(zeek_certs),
            "with_issues": sum(1 for c in zeek_certs if c.get("has_issues")),
            "entries": zeek_certs[:100],  # Limit entries
        },
        "alerts": {
            "self_signed_count": self_signed_count,
            "expired_count": expired_count,
            "high_risk_count": high_risk_count,
        },
    }

    if phase:
        alerts = result["alerts"]
        alert_msgs = []
        if alerts["self_signed_count"]:
            alert_msgs.append(f"{alerts['self_signed_count']} self-signed")
        if alerts["expired_count"]:
            alert_msgs.append(f"{alerts['expired_count']} expired")
        if alerts["high_risk_count"]:
            alert_msgs.append(f"{alerts['high_risk_count']} high-risk")

        summary = f"Found {len(unique_certs)} certificates"
        if zeek_certs:
            summary += f", {len(zeek_certs)} SSL connections"
        if alert_msgs:
            summary += f". Alerts: {', '.join(alert_msgs)}"
        phase.done(summary)

    return result
