# Phase 3 Implementation Plan

## Overview

Phase 3 adds three major features:
1. **YARA Rule Scanning** - Malware detection on carved files
2. **PDF Report Generation** - Professional PDF export
3. **Case Management** - Organize analyses into cases

---

## 1. YARA Rule Scanning

### 1.1 Architecture

```
app/pipeline/yara_scan.py     # Core YARA scanner
app/utils/yara_rules.py       # Rule management
app/data/yara/                # Default rule sets
  ├── malware_signatures.yar
  ├── suspicious_strings.yar
  └── custom/                 # User rules
```

### 1.2 Data Structures

```python
@dataclass
class YARAMatch:
    rule_name: str
    rule_tags: list[str]
    meta: dict[str, Any]
    strings: list[tuple[int, str, bytes]]  # offset, identifier, data
    file_path: str
    file_hash: str

@dataclass
class YARAScanResult:
    file_path: str
    file_hash: str
    file_size: int
    matches: list[YARAMatch]
    scan_time: float
    error: str | None
```

### 1.3 Core Functions

```python
class YARAScanner:
    def __init__(self, rules_dirs: list[str] = None):
        """Initialize with rule directories."""

    def load_rules(self) -> int:
        """Compile all YARA rules, return count."""

    def add_custom_rules(self, rules_path: str) -> None:
        """Add custom rule file/directory."""

    def scan_file(self, file_path: str) -> YARAScanResult:
        """Scan single file."""

    def scan_carved(self, carved: list[dict], phase: PhaseHandle) -> dict:
        """Scan all carved files with progress tracking."""
```

### 1.4 Default Rules

Include curated rules for:
- Common malware signatures (PE headers, shellcode)
- Suspicious strings (URLs, IPs, base64)
- File type detection (PE, ELF, scripts)
- Packed/obfuscated indicators

### 1.5 UI Integration

- Add to Raw Data tab under "Carved HTTP payloads"
- Show scan results table with severity indicators
- Allow rule file upload
- Export matches as CSV/JSON

### 1.6 Pipeline Integration

```python
# In main.py, after carving phase
if carved and st.session_state.get("cfg_do_yara", True):
    with phases.phase("yara_scan", "YARA Scanning") as phase:
        scanner = YARAScanner()
        yara_results = scanner.scan_carved(carved, phase)
        st.session_state["yara_results"] = yara_results
```

---

## 2. PDF Report Generation

### 2.1 Architecture

```
app/reports/
  ├── pdf_generator.py        # PDF generation engine
  ├── templates/
  │   ├── default.html        # HTML template
  │   └── styles.css          # Report styles
  └── assets/
      └── logo.png            # Optional branding
```

### 2.2 Data Structures

```python
@dataclass
class ReportConfig:
    title: str
    analyst: str
    organization: str
    classification: str  # TLP marking
    include_charts: bool
    include_raw_data: bool
    language: str

@dataclass
class PDFReport:
    content: bytes
    filename: str
    page_count: int
    generated_at: datetime
```

### 2.3 Core Functions

```python
class PDFReportGenerator:
    def __init__(self, config: ReportConfig = None):
        """Initialize with optional config."""

    def generate(self,
                 report_md: str,
                 features: dict,
                 osint: dict,
                 yara_results: dict = None,
                 case_info: dict = None) -> PDFReport:
        """Generate complete PDF report."""

    def _render_cover_page(self) -> str:
        """Generate cover page HTML."""

    def _render_executive_summary(self, report_md: str) -> str:
        """Extract and format executive summary."""

    def _render_ioc_table(self, features: dict, osint: dict) -> str:
        """Generate IOC summary table."""

    def _render_timeline(self, features: dict) -> str:
        """Generate flow timeline visualization."""

    def _render_appendix(self, raw_data: dict) -> str:
        """Generate raw data appendix."""
```

### 2.4 PDF Engine

Use `weasyprint` for HTML-to-PDF conversion:
- Professional typography
- Charts as embedded images
- Table formatting
- Page headers/footers
- Table of contents

### 2.5 Report Sections

1. **Cover Page**: Title, analyst, date, classification
2. **Table of Contents**: Auto-generated
3. **Executive Summary**: From LLM report
4. **Key Findings**: Threat indicators
5. **IOC Summary**: IPs, domains, hashes in table
6. **OSINT Correlation**: Enrichment results
7. **YARA Matches**: If scanned
8. **Timeline Analysis**: Flow visualization
9. **Appendix**: Raw data tables

### 2.6 UI Integration

- Add "Export PDF" button in Dashboard tab
- Options dialog for report configuration
- Progress indicator during generation
- Direct download via `st.download_button`

---

## 3. Case Management

### 3.1 Architecture

```
app/database/
  ├── models.py               # SQLAlchemy models
  ├── repository.py           # CRUD operations
  └── migrations/             # Schema migrations

app/ui/cases_tab.py           # Case management UI
```

### 3.2 Database Schema

```sql
-- Cases table
CREATE TABLE cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open',  -- open, in_progress, closed
    severity TEXT DEFAULT 'medium',  -- low, medium, high, critical
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP
);

-- Analyses linked to cases
CREATE TABLE analyses (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id),
    pcap_path TEXT NOT NULL,
    pcap_hash TEXT,
    packet_count INTEGER,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    features_json TEXT,  -- Compressed JSON
    osint_json TEXT,
    report_md TEXT,
    yara_json TEXT
);

-- IOCs extracted from analyses
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT REFERENCES analyses(id),
    ioc_type TEXT NOT NULL,  -- ip, domain, hash, ja3
    value TEXT NOT NULL,
    context TEXT,
    severity TEXT,
    UNIQUE(analysis_id, ioc_type, value)
);

-- User notes
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT REFERENCES cases(id),
    analysis_id TEXT REFERENCES analyses(id),
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Tags for organization
CREATE TABLE tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE case_tags (
    case_id TEXT REFERENCES cases(id),
    tag_id INTEGER REFERENCES tags(id),
    PRIMARY KEY (case_id, tag_id)
);

-- Indexes
CREATE INDEX idx_analyses_case ON analyses(case_id);
CREATE INDEX idx_iocs_analysis ON iocs(analysis_id);
CREATE INDEX idx_iocs_type_value ON iocs(ioc_type, value);
CREATE INDEX idx_notes_case ON notes(case_id);
```

### 3.3 Data Models

```python
@dataclass
class Case:
    id: str
    title: str
    description: str
    status: CaseStatus  # Enum: OPEN, IN_PROGRESS, CLOSED
    severity: Severity  # Enum: LOW, MEDIUM, HIGH, CRITICAL
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    tags: list[str]
    analyses: list[Analysis]
    notes: list[Note]

@dataclass
class Analysis:
    id: str
    case_id: str
    pcap_path: str
    pcap_hash: str
    packet_count: int
    analyzed_at: datetime
    features: dict
    osint: dict
    report: str
    yara_results: dict | None
    iocs: list[IOC]

@dataclass
class IOC:
    ioc_type: IOCType  # Enum: IP, DOMAIN, HASH, JA3, URL
    value: str
    context: str
    severity: Severity

@dataclass
class Note:
    id: int
    content: str
    created_at: datetime
    updated_at: datetime | None
```

### 3.4 Repository Pattern

```python
class CaseRepository:
    def __init__(self, db_path: str = None):
        """Initialize with database path."""

    # Case CRUD
    def create_case(self, case: Case) -> str:
        """Create new case, return ID."""

    def get_case(self, case_id: str) -> Case | None:
        """Get case by ID with all relations."""

    def list_cases(self,
                   status: CaseStatus = None,
                   tags: list[str] = None,
                   search: str = None) -> list[Case]:
        """List cases with optional filters."""

    def update_case(self, case: Case) -> None:
        """Update case metadata."""

    def delete_case(self, case_id: str) -> None:
        """Delete case and all related data."""

    # Analysis operations
    def save_analysis(self, analysis: Analysis) -> str:
        """Save analysis to case."""

    def get_analysis(self, analysis_id: str) -> Analysis | None:
        """Get analysis by ID."""

    # IOC operations
    def extract_iocs(self, analysis: Analysis) -> list[IOC]:
        """Extract IOCs from analysis results."""

    def search_iocs(self, value: str) -> list[tuple[IOC, Case]]:
        """Search IOCs across all cases."""

    # Note operations
    def add_note(self, case_id: str, content: str) -> int:
        """Add note to case."""

    def update_note(self, note_id: int, content: str) -> None:
        """Update existing note."""

    # Tag operations
    def add_tag(self, case_id: str, tag: str) -> None:
        """Add tag to case."""

    def remove_tag(self, case_id: str, tag: str) -> None:
        """Remove tag from case."""

    def list_tags(self) -> list[str]:
        """List all tags."""
```

### 3.5 UI Components

```python
# app/ui/cases_tab.py

def render_cases_tab():
    """Main cases tab with list and detail views."""

def render_case_list():
    """Case list with filters and search."""

def render_case_detail(case_id: str):
    """Single case view with analyses, notes, IOCs."""

def render_case_form(case: Case = None):
    """Create/edit case form."""

def render_analysis_detail(analysis_id: str):
    """Analysis detail within case context."""

def render_ioc_search():
    """Cross-case IOC search."""

def render_case_export(case_id: str):
    """Export case as archive (JSON + files)."""
```

### 3.6 Integration Points

1. **Save to Case**: Button after analysis completes
2. **Load from Case**: Select case to view previous analysis
3. **Quick Case**: Auto-create case from current session
4. **IOC Correlation**: Show if IOC seen in other cases

---

## 4. Implementation Order

### Step 1: YARA Scanning (Day 1)
1. Create `app/pipeline/yara_scan.py`
2. Create `app/utils/yara_rules.py`
3. Add default rules in `app/data/yara/`
4. Integrate into pipeline
5. Add UI in `layout.py`
6. Write tests

### Step 2: PDF Reports (Day 2)
1. Create `app/reports/pdf_generator.py`
2. Create HTML templates
3. Add report config options
4. Integrate into Dashboard
5. Write tests

### Step 3: Case Management (Day 3-4)
1. Create database models
2. Create repository layer
3. Create cases UI tab
4. Integrate with pipeline
5. Add IOC search
6. Write tests

### Step 4: Integration (Day 5)
1. Cross-feature integration
2. End-to-end testing
3. Documentation
4. Performance optimization

---

## 5. Dependencies

```
# requirements.txt additions
yara-python>=4.3.0        # YARA scanning
weasyprint>=60.0          # PDF generation
Jinja2>=3.1.0             # Report templates
```

---

## 6. File Summary

### New Files
```
app/
├── pipeline/
│   └── yara_scan.py          # YARA scanner
├── utils/
│   └── yara_rules.py         # Rule management
├── reports/
│   ├── __init__.py
│   ├── pdf_generator.py      # PDF generation
│   └── templates/
│       ├── report.html
│       └── styles.css
├── database/
│   ├── __init__.py
│   ├── models.py             # SQLAlchemy models
│   └── repository.py         # CRUD operations
├── ui/
│   └── cases_tab.py          # Case management UI
└── data/
    └── yara/
        ├── malware.yar
        ├── suspicious.yar
        └── filetypes.yar

tests/
├── test_yara_scan.py
├── test_pdf_generator.py
└── test_case_management.py
```

### Modified Files
```
app/main.py                   # Add YARA phase, Cases tab
app/ui/layout.py              # Add YARA results, PDF button
requirements.txt              # Add dependencies
```

---

## 7. Testing Strategy

### Unit Tests
- YARA rule compilation and matching
- PDF generation from markdown
- Database CRUD operations
- IOC extraction logic

### Integration Tests
- Full pipeline with YARA scanning
- PDF export with all data types
- Case creation from analysis
- Cross-case IOC search

### Manual Testing
- Upload various file types for YARA
- Verify PDF formatting and content
- Test case workflow end-to-end
- Performance with large PCAPs
