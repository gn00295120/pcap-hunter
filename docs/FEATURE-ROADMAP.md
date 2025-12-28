# PCAP Hunter Feature Roadmap

## Overview

This document outlines the planned features for PCAP Hunter, prioritized by implementation complexity and user value.

---

## Phase 1: Quick Wins (Low Effort, High Value)

### 1.1 CSV/JSON Export

**Goal**: Allow users to export analysis results for external processing or archival.

**Scope**:
- Export flow data, Zeek logs, OSINT results, and beaconing scores
- Support CSV (for spreadsheets) and JSON (for programmatic use)
- Include filtered views (respect current dashboard filters)

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Export utilities | `app/utils/export.py` | New module |
| UI buttons | `app/ui/results_tab.py` | Add export buttons per section |
| Streamlit download | `app/main.py` | Wire `st.download_button` |

**Technical Details**:
```python
# app/utils/export.py
def export_to_csv(data: list[dict], filename: str) -> bytes:
    """Convert list of dicts to CSV bytes."""

def export_to_json(data: Any, filename: str, indent: int = 2) -> bytes:
    """Convert data to formatted JSON bytes."""
```

**Dependencies**: None (uses standard library)

---

### 1.2 Configuration Persistence

**Goal**: Save user settings (API keys, thresholds, preferences) across sessions.

**Scope**:
- Persist: LLM endpoint, API keys, analysis toggles, threshold values
- Storage: Local JSON file (`.pcap_hunter_config.json`)
- Security: Encrypt sensitive values (API keys)

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Config manager | `app/utils/config_manager.py` | New module |
| Encryption | `app/security/crypto.py` | New module (Fernet) |
| UI integration | `app/ui/sidebar.py` | Load/save buttons |

**Technical Details**:
```python
# app/utils/config_manager.py
class ConfigManager:
    def load(self) -> dict: ...
    def save(self, config: dict) -> None: ...
    def get(self, key: str, default: Any = None) -> Any: ...
```

**Dependencies**: `cryptography` (for Fernet encryption)

---

### 1.3 OSINT Response Caching

**Goal**: Cache OSINT API responses to reduce API calls and improve response time.

**Scope**:
- Cache by IP/domain with configurable TTL (default: 24 hours)
- Storage: SQLite database (`data/osint_cache.db`)
- Manual cache invalidation UI

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Cache layer | `app/pipeline/osint_cache.py` | New module |
| OSINT integration | `app/pipeline/osint.py` | Check cache before API call |
| UI controls | `app/ui/sidebar.py` | Cache stats & clear button |

**Technical Details**:
```python
# app/pipeline/osint_cache.py
class OSINTCache:
    def __init__(self, db_path: str, ttl_hours: int = 24): ...
    def get(self, indicator: str, provider: str) -> dict | None: ...
    def set(self, indicator: str, provider: str, data: dict) -> None: ...
    def invalidate(self, indicator: str = None) -> int: ...
```

**Dependencies**: `sqlite3` (standard library)

---

### 1.4 JA3/JA3S Fingerprint Lookup

**Goal**: Identify TLS client/server implementations using JA3 fingerprints.

**Scope**:
- Calculate JA3/JA3S from TLS handshake fields
- Lookup against known fingerprint databases
- Display in SSL/TLS analysis section

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| JA3 calculator | `app/pipeline/ja3.py` | New module |
| Fingerprint DB | `app/data/ja3_fingerprints.json` | Static lookup table |
| Zeek integration | `app/pipeline/zeek.py` | Parse `ssl.log` JA3 fields |
| UI display | `app/ui/results_tab.py` | Add JA3 column to SSL table |

**Technical Details**:
```python
# app/pipeline/ja3.py
def calculate_ja3(version: str, ciphers: list, extensions: list,
                  curves: list, point_formats: list) -> str:
    """Calculate JA3 fingerprint hash."""

def lookup_ja3(ja3_hash: str) -> dict | None:
    """Lookup JA3 in known fingerprint database."""
```

**Dependencies**: None (Zeek already extracts JA3)

---

## Phase 2: Medium Effort Features

### 2.1 DNS Query/Response Carving

**Goal**: Extract and analyze DNS queries and responses for threat detection.

**Scope**:
- Parse DNS packets for query names, types, and responses
- Detect suspicious patterns (DGA, DNS tunneling, fast flux)
- Visualize DNS activity timeline

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| DNS carver | `app/pipeline/dns_carve.py` | New module |
| DGA detection | `app/pipeline/dns_analysis.py` | Entropy/pattern analysis |
| Zeek DNS parsing | `app/pipeline/zeek.py` | Enhanced `dns.log` parsing |
| UI visualization | `app/ui/dns_tab.py` | New tab |

**Technical Details**:
```python
# app/pipeline/dns_analysis.py
def detect_dga(domain: str) -> float:
    """Return DGA probability score (0-1)."""

def detect_tunneling(dns_records: list[dict]) -> dict:
    """Analyze for DNS tunneling indicators."""

def detect_fast_flux(domain: str, responses: list[dict]) -> bool:
    """Check for fast-flux DNS behavior."""
```

**Dependencies**: None (uses existing Zeek/PyShark)

---

### 2.2 Multi-PCAP Batch Analysis

**Goal**: Analyze multiple PCAP files together with correlation across files.

**Scope**:
- Upload multiple PCAPs
- Correlate IPs/domains across files
- Timeline aggregation
- Merged reporting

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Batch processor | `app/pipeline/batch.py` | New module |
| Session merger | `app/pipeline/merge.py` | New module |
| UI multi-upload | `app/ui/upload_tab.py` | Multi-file upload |
| Progress tracking | `app/pipeline/state.py` | Multi-file progress |

**Technical Details**:
```python
# app/pipeline/batch.py
class BatchProcessor:
    def __init__(self, pcap_paths: list[str]): ...
    def process_all(self, phase: PhaseHandle) -> dict: ...
    def correlate(self) -> dict: ...
```

**Dependencies**: None

---

### 2.3 SSL/TLS Certificate Extraction

**Goal**: Extract and display certificate details from TLS handshakes.

**Scope**:
- Extract X.509 certificates from PCAP
- Parse certificate fields (subject, issuer, validity, SANs)
- Certificate chain validation
- Export certificates as PEM

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Cert extractor | `app/pipeline/tls_certs.py` | New module |
| PyShark integration | `app/pipeline/pyshark_pass.py` | Add TLS parsing |
| UI display | `app/ui/tls_tab.py` | New tab or section |

**Technical Details**:
```python
# app/pipeline/tls_certs.py
@dataclass
class Certificate:
    subject: dict
    issuer: dict
    not_before: datetime
    not_after: datetime
    serial: str
    sans: list[str]
    fingerprint_sha256: str

def extract_certificates(pcap_path: str) -> list[Certificate]: ...
def validate_chain(certs: list[Certificate]) -> dict: ...
```

**Dependencies**: `cryptography` (for X.509 parsing)

---

## Phase 3: High Effort Features

### 3.1 YARA Rule Scanning

**Goal**: Scan carved files against YARA rules for malware detection.

**Scope**:
- Integrate YARA engine
- Include default rule sets (malware signatures)
- Support custom rule upload
- Display matches with context

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| YARA scanner | `app/pipeline/yara_scan.py` | New module |
| Rule manager | `app/utils/yara_rules.py` | Load/manage rules |
| Default rules | `app/data/yara/` | Curated rule sets |
| UI integration | `app/ui/carve_tab.py` | Scan results display |

**Technical Details**:
```python
# app/pipeline/yara_scan.py
class YARAScanner:
    def __init__(self, rules_dir: str = None): ...
    def add_rules(self, rules_path: str) -> None: ...
    def scan_file(self, file_path: str) -> list[YARAMatch]: ...
    def scan_directory(self, dir_path: str, phase: PhaseHandle) -> dict: ...

@dataclass
class YARAMatch:
    rule: str
    tags: list[str]
    strings: list[tuple[int, str, bytes]]
    meta: dict
```

**Dependencies**: `yara-python`

---

### 3.2 PDF Report Generation

**Goal**: Generate professional PDF reports for documentation and sharing.

**Scope**:
- Executive summary
- Detailed findings with visualizations
- IOC list
- Timeline of events
- Customizable branding

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Report generator | `app/reports/pdf_report.py` | New module |
| Templates | `app/reports/templates/` | Jinja2 templates |
| Chart export | `app/utils/chart_export.py` | Export Plotly as images |
| UI button | `app/ui/report_tab.py` | Generate PDF button |

**Technical Details**:
```python
# app/reports/pdf_report.py
class PDFReportGenerator:
    def __init__(self, analysis_data: dict, template: str = "default"): ...
    def generate(self, output_path: str) -> None: ...

    def _render_executive_summary(self) -> str: ...
    def _render_flow_analysis(self) -> str: ...
    def _render_osint_findings(self) -> str: ...
    def _render_timeline(self) -> str: ...
    def _render_ioc_table(self) -> str: ...
```

**Dependencies**: `weasyprint` or `reportlab`, `jinja2`

---

### 3.3 Case Management

**Goal**: Organize analyses into cases with notes, tags, and history.

**Scope**:
- Create/manage cases
- Link multiple PCAPs to a case
- Add analyst notes and tags
- Search across cases
- Export case archive

**Implementation**:

| Component | File | Changes |
|-----------|------|---------|
| Case model | `app/models/case.py` | New module |
| Database | `app/db/cases.py` | SQLite persistence |
| Case API | `app/api/cases.py` | CRUD operations |
| UI | `app/ui/cases_tab.py` | Full case management UI |

**Technical Details**:
```python
# app/models/case.py
@dataclass
class Case:
    id: str
    title: str
    description: str
    created_at: datetime
    updated_at: datetime
    tags: list[str]
    pcaps: list[str]
    notes: list[Note]
    iocs: list[IOC]
    status: CaseStatus

# app/db/cases.py
class CaseDB:
    def create(self, case: Case) -> str: ...
    def get(self, case_id: str) -> Case | None: ...
    def update(self, case: Case) -> None: ...
    def delete(self, case_id: str) -> None: ...
    def search(self, query: str, tags: list[str] = None) -> list[Case]: ...
```

**Dependencies**: `sqlite3`, possibly `sqlalchemy`

---

## Implementation Priority Matrix

| Feature | Effort | Value | Priority |
|---------|--------|-------|----------|
| CSV/JSON Export | Low | High | P0 |
| Config Persistence | Low | High | P0 |
| OSINT Caching | Low | Medium | P1 |
| JA3 Lookup | Low | Medium | P1 |
| DNS Carving | Medium | High | P1 |
| Multi-PCAP | Medium | High | P2 |
| TLS Cert Extraction | Medium | Medium | P2 |
| YARA Scanning | High | High | P2 |
| PDF Reports | High | Medium | P3 |
| Case Management | High | High | P3 |

---

## Dependencies Summary

**New packages required**:
```
cryptography>=41.0.0   # Config encryption, TLS cert parsing
yara-python>=4.3.0     # YARA scanning (optional)
weasyprint>=60.0       # PDF generation (optional)
jinja2>=3.1.0          # Report templates (optional)
```

---

## Architecture Considerations

### Module Organization

```
app/
├── pipeline/
│   ├── dns_carve.py       # New: DNS carving
│   ├── dns_analysis.py    # New: DGA/tunneling detection
│   ├── ja3.py             # New: JA3 fingerprinting
│   ├── osint_cache.py     # New: OSINT caching
│   ├── tls_certs.py       # New: Certificate extraction
│   ├── yara_scan.py       # New: YARA scanning
│   └── batch.py           # New: Multi-PCAP processing
├── utils/
│   ├── export.py          # New: CSV/JSON export
│   ├── config_manager.py  # New: Config persistence
│   └── yara_rules.py      # New: YARA rule management
├── reports/
│   ├── pdf_report.py      # New: PDF generation
│   └── templates/         # New: Report templates
├── models/
│   └── case.py            # New: Case data model
├── db/
│   └── cases.py           # New: Case database
└── security/
    └── crypto.py          # New: Encryption utilities
```

### Data Flow

```
                    ┌─────────────────┐
                    │   PCAP Upload   │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌───────────┐    ┌───────────┐    ┌───────────┐
    │   Zeek    │    │  PyShark  │    │  Tshark   │
    └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
          │                │                │
          │    ┌───────────┴───────────┐    │
          │    ▼                       ▼    │
          │  ┌───────┐           ┌───────┐  │
          │  │  JA3  │           │  DNS  │  │
          │  └───────┘           │ Carve │  │
          │                      └───────┘  │
          │                                 │
          └──────────────┬──────────────────┘
                         ▼
              ┌─────────────────────┐
              │   OSINT Enrichment  │◄──── Cache
              └──────────┬──────────┘
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
     ┌──────────┐ ┌──────────┐ ┌──────────┐
     │ Beaconing│ │   YARA   │ │   TLS    │
     │ Detection│ │  Scanning│ │  Certs   │
     └──────────┘ └──────────┘ └──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │    LLM Analysis     │
              └──────────┬──────────┘
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
     ┌──────────┐ ┌──────────┐ ┌──────────┐
     │  Export  │ │   PDF    │ │   Case   │
     │ CSV/JSON │ │  Report  │ │   Mgmt   │
     └──────────┘ └──────────┘ └──────────┘
```

---

## Version Milestones

### v0.3.0 - Export & Persistence
- CSV/JSON Export
- Configuration Persistence
- OSINT Caching

### v0.4.0 - Enhanced Analysis
- JA3/JA3S Fingerprinting
- DNS Carving & Analysis
- SSL/TLS Certificate Extraction

### v0.5.0 - Advanced Features
- Multi-PCAP Batch Analysis
- YARA Rule Scanning

### v1.0.0 - Enterprise Ready
- PDF Report Generation
- Case Management System
- Full documentation
