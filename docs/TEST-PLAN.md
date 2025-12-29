# PCAP Hunter Test Plan

## Overview

This document outlines the testing strategy for new features in PCAP Hunter. It covers unit tests, integration tests, and end-to-end testing approaches.

---

## Testing Philosophy

1. **Test-First Development**: Write tests before implementation where possible
2. **High Coverage on Critical Paths**: Security and data processing code must have >90% coverage
3. **Mocked External Dependencies**: API calls, file system operations use mocks
4. **Realistic Test Data**: Use sanitized PCAP samples for integration tests

---

## Test Infrastructure

### Directory Structure

```
tests/
├── conftest.py              # Shared fixtures
├── fixtures/                # Test data
│   ├── sample.pcap          # Small test PCAP
│   ├── dns_tunnel.pcap      # DNS tunneling sample
│   ├── beacon.pcap          # C2 beaconing sample
│   └── malware_carved.bin   # Test carved file
├── unit/                    # Unit tests
│   ├── test_export.py
│   ├── test_config_manager.py
│   ├── test_osint_cache.py
│   ├── test_ja3.py
│   ├── test_dns_analysis.py
│   ├── test_tls_certs.py
│   ├── test_yara_scan.py
│   └── test_case_model.py
├── integration/             # Integration tests
│   ├── test_pipeline_export.py
│   ├── test_batch_analysis.py
│   └── test_case_workflow.py
└── e2e/                     # End-to-end tests
    └── test_full_analysis.py
```

### Shared Fixtures (`conftest.py`)

```python
import pytest
from pathlib import Path

@pytest.fixture
def sample_pcap():
    """Path to small test PCAP file."""
    return Path(__file__).parent / "fixtures" / "sample.pcap"

@pytest.fixture
def sample_flows():
    """Sample flow data for testing."""
    return [
        {"src": "192.168.1.100", "dst": "8.8.8.8", "sport": 54321, "dport": 53,
         "proto": "DNS", "pkt_times": [1.0, 2.0, 3.0]},
        {"src": "192.168.1.100", "dst": "1.1.1.1", "sport": 54322, "dport": 443,
         "proto": "TLS", "pkt_times": [1.5, 2.5, 3.5]},
    ]

@pytest.fixture
def mock_osint_response():
    """Sample OSINT API response."""
    return {
        "greynoise": {"seen": True, "classification": "malicious"},
        "abuseipdb": {"data": {"abuseConfidenceScore": 75}},
    }

@pytest.fixture
def temp_data_dir(tmp_path):
    """Temporary directory for test outputs."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir
```

---

## Phase 1: Quick Wins Test Cases

### 1.1 CSV/JSON Export Tests

**File**: `tests/unit/test_export.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| EXP-001 | test_export_flows_csv | Export flows to CSV | List of flow dicts | Valid CSV bytes with headers |
| EXP-002 | test_export_flows_json | Export flows to JSON | List of flow dicts | Valid JSON bytes |
| EXP-003 | test_export_empty_data | Handle empty input | Empty list | Empty CSV/JSON structure |
| EXP-004 | test_export_special_chars | Handle special characters | Flows with unicode | Properly escaped output |
| EXP-005 | test_export_nested_data | Handle nested dicts | OSINT results | Flattened CSV / nested JSON |
| EXP-006 | test_export_large_dataset | Performance test | 100k flows | Completes in <5s |

```python
# tests/unit/test_export.py
import json
import csv
from io import StringIO
from app.utils.export import export_to_csv, export_to_json

def test_export_flows_csv(sample_flows):
    result = export_to_csv(sample_flows, "flows.csv")
    assert isinstance(result, bytes)
    reader = csv.DictReader(StringIO(result.decode()))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["src"] == "192.168.1.100"

def test_export_flows_json(sample_flows):
    result = export_to_json(sample_flows, "flows.json")
    data = json.loads(result)
    assert len(data) == 2
    assert data[0]["proto"] == "DNS"

def test_export_empty_data():
    result = export_to_csv([], "empty.csv")
    assert result == b""  # or just headers

def test_export_special_chars():
    flows = [{"src": "192.168.1.1", "note": "Test \u2605 unicode"}]
    result = export_to_csv(flows, "special.csv")
    assert "unicode" in result.decode("utf-8")
```

---

### 1.2 Configuration Persistence Tests

**File**: `tests/unit/test_config_manager.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| CFG-001 | test_save_load_config | Round-trip save/load | Config dict | Same values |
| CFG-002 | test_encrypt_api_keys | API keys encrypted | Config with keys | Encrypted in file |
| CFG-003 | test_missing_config_file | Handle missing file | No file exists | Returns defaults |
| CFG-004 | test_corrupted_config | Handle corrupted JSON | Invalid JSON | Returns defaults, logs error |
| CFG-005 | test_partial_config | Merge with defaults | Partial config | Merged with defaults |
| CFG-006 | test_config_isolation | Per-project configs | Two projects | Separate configs |

```python
# tests/unit/test_config_manager.py
from app.utils.config_manager import ConfigManager

def test_save_load_config(temp_data_dir):
    config_path = temp_data_dir / ".config.json"
    manager = ConfigManager(config_path)

    original = {"llm_endpoint": "http://localhost:1234", "vt_key": "secret123"}
    manager.save(original)

    loaded = manager.load()
    assert loaded["llm_endpoint"] == original["llm_endpoint"]
    assert loaded["vt_key"] == original["vt_key"]

def test_encrypt_api_keys(temp_data_dir):
    config_path = temp_data_dir / ".config.json"
    manager = ConfigManager(config_path)

    manager.save({"vt_key": "my_secret_key"})

    # Read raw file - API key should be encrypted
    raw = config_path.read_text()
    assert "my_secret_key" not in raw
    assert "encrypted:" in raw or "ENC[" in raw

def test_missing_config_file(temp_data_dir):
    config_path = temp_data_dir / "nonexistent.json"
    manager = ConfigManager(config_path)

    config = manager.load()
    assert config == manager.defaults
```

---

### 1.3 OSINT Cache Tests

**File**: `tests/unit/test_osint_cache.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| OSC-001 | test_cache_miss | Query uncached IP | New IP | None |
| OSC-002 | test_cache_hit | Query cached IP | Cached IP | Cached data |
| OSC-003 | test_cache_expiry | TTL expiration | Expired entry | None |
| OSC-004 | test_cache_invalidate | Manual invalidation | Cached IP | Entry removed |
| OSC-005 | test_cache_stats | Get cache statistics | After operations | Correct counts |
| OSC-006 | test_concurrent_access | Thread safety | Parallel writes | No corruption |

```python
# tests/unit/test_osint_cache.py
import time
from app.pipeline.osint_cache import OSINTCache

def test_cache_miss(temp_data_dir):
    cache = OSINTCache(temp_data_dir / "osint.db")
    result = cache.get("8.8.8.8", "greynoise")
    assert result is None

def test_cache_hit(temp_data_dir, mock_osint_response):
    cache = OSINTCache(temp_data_dir / "osint.db")
    cache.set("8.8.8.8", "greynoise", mock_osint_response["greynoise"])

    result = cache.get("8.8.8.8", "greynoise")
    assert result == mock_osint_response["greynoise"]

def test_cache_expiry(temp_data_dir):
    cache = OSINTCache(temp_data_dir / "osint.db", ttl_seconds=1)
    cache.set("8.8.8.8", "greynoise", {"test": True})

    time.sleep(1.5)
    result = cache.get("8.8.8.8", "greynoise")
    assert result is None

def test_cache_invalidate(temp_data_dir):
    cache = OSINTCache(temp_data_dir / "osint.db")
    cache.set("8.8.8.8", "greynoise", {"test": True})
    cache.set("1.1.1.1", "greynoise", {"test": True})

    count = cache.invalidate("8.8.8.8")
    assert count == 1
    assert cache.get("8.8.8.8", "greynoise") is None
    assert cache.get("1.1.1.1", "greynoise") is not None
```

---

### 1.4 JA3 Fingerprint Tests

**File**: `tests/unit/test_ja3.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| JA3-001 | test_calculate_ja3 | Calculate JA3 hash | TLS params | Correct MD5 hash |
| JA3-002 | test_known_fingerprint | Lookup known JA3 | Chrome JA3 | "Google Chrome" |
| JA3-003 | test_unknown_fingerprint | Lookup unknown JA3 | Random hash | None |
| JA3-004 | test_ja3s_calculation | Calculate JA3S | Server params | Correct hash |
| JA3-005 | test_malware_fingerprint | Detect malware JA3 | Cobalt Strike JA3 | Malware match |

```python
# tests/unit/test_ja3.py
from app.pipeline.ja3 import calculate_ja3, lookup_ja3

def test_calculate_ja3():
    # Known Chrome JA3 parameters
    ja3_hash = calculate_ja3(
        version="771",  # TLS 1.2
        ciphers=["49195", "49196", "49199", "49200"],
        extensions=["0", "23", "65281"],
        curves=["29", "23", "24"],
        point_formats=["0"]
    )
    assert len(ja3_hash) == 32  # MD5 hash
    assert ja3_hash.isalnum()

def test_known_fingerprint():
    # Well-known Chrome JA3
    chrome_ja3 = "769,47-53-5-10-49171-49172-49161-49162,0-10-11,23-24,0"
    result = lookup_ja3(calculate_ja3_from_string(chrome_ja3))
    assert result is not None
    assert "Chrome" in result.get("client", "")

def test_unknown_fingerprint():
    result = lookup_ja3("0" * 32)
    assert result is None

def test_malware_fingerprint():
    # Known Cobalt Strike JA3
    cobalt_ja3 = "72a589da586844d7f0818ce684948eea"
    result = lookup_ja3(cobalt_ja3)
    assert result is not None
    assert result.get("malware", False) or "Cobalt" in result.get("notes", "")
```

---

## Phase 2: Medium Effort Test Cases

### 2.1 DNS Analysis Tests

**File**: `tests/unit/test_dns_analysis.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| DNS-001 | test_normal_domain | Score normal domain | "google.com" | Low DGA score (<0.3) |
| DNS-002 | test_dga_domain | Detect DGA domain | "x7k9m2p4.com" | High DGA score (>0.7) |
| DNS-003 | test_subdomain_entropy | High entropy subdomain | Long random subdomain | Tunneling flag |
| DNS-004 | test_fast_flux | Detect fast-flux | Many IPs, short TTL | Fast-flux detected |
| DNS-005 | test_txt_tunneling | TXT record tunneling | Large TXT responses | Tunneling detected |

```python
# tests/unit/test_dns_analysis.py
from app.pipeline.dns_analysis import detect_dga, detect_tunneling, detect_fast_flux

def test_normal_domain():
    score = detect_dga("google.com")
    assert score < 0.3

def test_dga_domain():
    # Typical DGA-generated domain
    score = detect_dga("x7k9m2p4q1.com")
    assert score > 0.7

def test_subdomain_entropy():
    dns_records = [
        {"query": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil.com", "type": "A"}
    ]
    result = detect_tunneling(dns_records)
    assert result["high_entropy_subdomains"] > 0

def test_fast_flux():
    # Same domain, many different IPs
    responses = [
        {"domain": "malware.com", "ip": f"1.2.3.{i}", "ttl": 60}
        for i in range(20)
    ]
    result = detect_fast_flux("malware.com", responses)
    assert result is True

def test_txt_tunneling():
    dns_records = [
        {"query": "data.evil.com", "type": "TXT",
         "answer": "VGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmc="}
    ]
    result = detect_tunneling(dns_records)
    assert result["suspicious_txt"] > 0
```

---

### 2.2 TLS Certificate Tests

**File**: `tests/unit/test_tls_certs.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| TLS-001 | test_extract_cert | Extract certificate | PCAP with TLS | Certificate object |
| TLS-002 | test_expired_cert | Detect expired cert | Expired cert | is_expired=True |
| TLS-003 | test_self_signed | Detect self-signed | Self-signed cert | is_self_signed=True |
| TLS-004 | test_cert_chain | Validate chain | Full chain | chain_valid=True |
| TLS-005 | test_san_extraction | Extract SANs | Cert with SANs | List of SANs |

```python
# tests/unit/test_tls_certs.py
from datetime import datetime, timedelta
from app.pipeline.tls_certs import Certificate, validate_chain

def test_extract_cert(sample_pcap):
    from app.pipeline.tls_certs import extract_certificates
    certs = extract_certificates(str(sample_pcap))
    assert len(certs) > 0
    assert isinstance(certs[0], Certificate)

def test_expired_cert():
    cert = Certificate(
        subject={"CN": "test.com"},
        issuer={"CN": "Test CA"},
        not_before=datetime.now() - timedelta(days=365),
        not_after=datetime.now() - timedelta(days=1),
        serial="1234",
        sans=["test.com"],
        fingerprint_sha256="abc123"
    )
    assert cert.is_expired()

def test_self_signed():
    cert = Certificate(
        subject={"CN": "test.com"},
        issuer={"CN": "test.com"},  # Same as subject
        not_before=datetime.now(),
        not_after=datetime.now() + timedelta(days=365),
        serial="1234",
        sans=["test.com"],
        fingerprint_sha256="abc123"
    )
    assert cert.is_self_signed()
```

---

### 2.3 Batch Analysis Tests

**File**: `tests/integration/test_batch_analysis.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| BAT-001 | test_multi_pcap | Process multiple PCAPs | 3 PCAPs | Combined results |
| BAT-002 | test_ip_correlation | Correlate IPs across | Related PCAPs | Correlation map |
| BAT-003 | test_timeline_merge | Merge timelines | Overlapping times | Unified timeline |
| BAT-004 | test_progress_tracking | Track batch progress | 5 PCAPs | 5 phase updates |

```python
# tests/integration/test_batch_analysis.py
from app.pipeline.batch import BatchProcessor

def test_multi_pcap(temp_data_dir):
    pcaps = [temp_data_dir / f"test{i}.pcap" for i in range(3)]
    # Create test PCAPs...

    processor = BatchProcessor([str(p) for p in pcaps])
    result = processor.process_all(phase=None)

    assert "combined_flows" in result
    assert len(result["file_results"]) == 3

def test_ip_correlation(temp_data_dir):
    # Two PCAPs with same malicious IP
    processor = BatchProcessor(["pcap1.pcap", "pcap2.pcap"])
    result = processor.correlate()

    assert "shared_ips" in result
    assert "shared_domains" in result
```

---

## Phase 3: High Effort Test Cases

### 3.1 YARA Scanning Tests

**File**: `tests/unit/test_yara_scan.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| YAR-001 | test_load_rules | Load YARA rules | Rule file | Rules compiled |
| YAR-002 | test_scan_clean | Scan clean file | Benign file | No matches |
| YAR-003 | test_scan_malware | Scan malware | Known malware | Matches found |
| YAR-004 | test_custom_rules | Use custom rules | User rule | Rule applied |
| YAR-005 | test_scan_directory | Batch scan | Directory | All files scanned |

```python
# tests/unit/test_yara_scan.py
from app.pipeline.yara_scan import YARAScanner, YARAMatch

def test_load_rules(temp_data_dir):
    rule_file = temp_data_dir / "test.yar"
    rule_file.write_text('''
rule TestRule {
    strings:
        $a = "malicious_string"
    condition:
        $a
}
''')
    scanner = YARAScanner()
    scanner.add_rules(str(rule_file))
    assert scanner.rule_count > 0

def test_scan_clean(temp_data_dir):
    clean_file = temp_data_dir / "clean.txt"
    clean_file.write_text("This is a normal file with no malicious content.")

    scanner = YARAScanner()
    matches = scanner.scan_file(str(clean_file))
    assert len(matches) == 0

def test_scan_malware(temp_data_dir):
    malware_file = temp_data_dir / "malware.bin"
    malware_file.write_text("Contains malicious_string for testing")

    rule_file = temp_data_dir / "test.yar"
    rule_file.write_text('''
rule TestMalware {
    strings:
        $a = "malicious_string"
    condition:
        $a
}
''')

    scanner = YARAScanner()
    scanner.add_rules(str(rule_file))
    matches = scanner.scan_file(str(malware_file))

    assert len(matches) == 1
    assert matches[0].rule == "TestMalware"
```

---

### 3.2 Case Management Tests

**File**: `tests/unit/test_case_model.py` & `tests/integration/test_case_workflow.py`

| Test ID | Test Name | Description | Input | Expected Output |
|---------|-----------|-------------|-------|-----------------|
| CAS-001 | test_create_case | Create new case | Case data | Case ID returned |
| CAS-002 | test_add_pcap | Add PCAP to case | Case + PCAP | PCAP linked |
| CAS-003 | test_add_note | Add analyst note | Case + note | Note saved |
| CAS-004 | test_search_cases | Search by keyword | Search query | Matching cases |
| CAS-005 | test_tag_filtering | Filter by tags | Tag list | Tagged cases |
| CAS-006 | test_export_case | Export case archive | Case ID | ZIP archive |

```python
# tests/unit/test_case_model.py
from app.models.case import Case, Note, CaseStatus
from app.db.cases import CaseDB

def test_create_case(temp_data_dir):
    db = CaseDB(temp_data_dir / "cases.db")

    case = Case(
        id=None,
        title="Suspicious Traffic Investigation",
        description="Investigating potential C2 traffic",
        tags=["c2", "malware"],
        pcaps=[],
        notes=[],
        status=CaseStatus.OPEN
    )

    case_id = db.create(case)
    assert case_id is not None

    retrieved = db.get(case_id)
    assert retrieved.title == "Suspicious Traffic Investigation"

def test_add_note(temp_data_dir):
    db = CaseDB(temp_data_dir / "cases.db")
    case_id = db.create(Case(title="Test Case", ...))

    note = Note(
        author="analyst1",
        content="Found suspicious beaconing pattern",
        created_at=datetime.now()
    )

    db.add_note(case_id, note)
    case = db.get(case_id)
    assert len(case.notes) == 1
    assert "beaconing" in case.notes[0].content

def test_search_cases(temp_data_dir):
    db = CaseDB(temp_data_dir / "cases.db")

    db.create(Case(title="APT29 Investigation", tags=["apt", "russia"]))
    db.create(Case(title="Ransomware Incident", tags=["ransomware"]))
    db.create(Case(title="APT28 Analysis", tags=["apt", "russia"]))

    results = db.search("APT")
    assert len(results) == 2

    results = db.search(tags=["russia"])
    assert len(results) == 2
```

---

## Integration Test Strategy

### Pipeline Integration Tests

**File**: `tests/integration/test_pipeline_export.py`

```python
def test_full_analysis_to_export(sample_pcap, temp_data_dir):
    """Test complete flow: PCAP -> Analysis -> Export"""
    from app.pipeline import run_full_analysis
    from app.utils.export import export_to_json

    # Run analysis
    result = run_full_analysis(str(sample_pcap), str(temp_data_dir))

    # Export results
    json_data = export_to_json(result["flows"], "flows.json")

    # Verify export
    import json
    exported = json.loads(json_data)
    assert len(exported) == len(result["flows"])
```

---

## End-to-End Test Strategy

### Full Workflow Test

**File**: `tests/e2e/test_full_analysis.py`

```python
def test_complete_workflow(sample_pcap, temp_data_dir):
    """Simulate complete user workflow"""
    # 1. Upload PCAP
    # 2. Configure analysis
    # 3. Run pipeline
    # 4. Verify results
    # 5. Export report
    pass
```

---

## Test Data Requirements

### Sample PCAPs Needed

| Filename | Purpose | Size | Content |
|----------|---------|------|---------|
| `sample.pcap` | Basic tests | <1MB | HTTP, DNS, TLS traffic |
| `beacon.pcap` | C2 detection | <1MB | Regular interval connections |
| `dns_tunnel.pcap` | DNS analysis | <1MB | DNS tunneling traffic |
| `malware_pcap` | YARA testing | <1MB | Traffic with malware indicators |
| `multi_protocol.pcap` | Protocol parsing | <5MB | Various protocols |

### Generating Test Data

```python
# scripts/generate_test_pcaps.py
from scapy.all import *

def create_beacon_pcap(output_path):
    """Create PCAP with beaconing pattern."""
    packets = []
    for i in range(100):
        pkt = IP(src="192.168.1.100", dst="10.0.0.1") / \
              TCP(sport=RandShort(), dport=443) / \
              Raw(load=b"beacon")
        pkt.time = i * 60  # 1 minute intervals
        packets.append(pkt)
    wrpcap(output_path, packets)
```

---

## Coverage Requirements

| Module | Required Coverage | Critical Paths |
|--------|-------------------|----------------|
| `app/utils/export.py` | 95% | All export functions |
| `app/utils/config_manager.py` | 90% | Encryption, load/save |
| `app/pipeline/osint_cache.py` | 90% | Cache operations |
| `app/pipeline/ja3.py` | 85% | Hash calculation |
| `app/pipeline/dns_analysis.py` | 85% | DGA detection |
| `app/pipeline/yara_scan.py` | 80% | Scan functions |
| `app/db/cases.py` | 90% | CRUD operations |

---

## CI/CD Test Configuration

### pytest.ini

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -v --cov=app --cov-report=html --cov-report=term-missing
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks integration tests
    e2e: marks end-to-end tests
```

### GitHub Actions Workflow

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
          sudo apt-get install -y tshark
      - name: Run tests
        run: pytest -v --cov=app
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

---

## Test Execution Plan

### Phase 1 (Quick Wins)
1. Write unit tests for export module
2. Write unit tests for config manager
3. Write unit tests for OSINT cache
4. Write unit tests for JA3 functions

### Phase 2 (Medium Effort)
1. Write DNS analysis unit tests
2. Write TLS certificate tests
3. Write batch processing integration tests

### Phase 3 (High Effort)
1. Write YARA scanning tests
2. Write case management unit tests
3. Write case workflow integration tests
4. Write end-to-end tests

---

## Mocking Strategy

### External APIs

```python
@pytest.fixture
def mock_virustotal(requests_mock):
    requests_mock.get(
        re.compile(r"https://www\.virustotal\.com/api/v3/.*"),
        json={"data": {"attributes": {"reputation": 0}}}
    )

@pytest.fixture
def mock_greynoise(requests_mock):
    requests_mock.get(
        re.compile(r"https://api\.greynoise\.io/v3/community/.*"),
        json={"seen": False, "classification": "benign"}
    )
```

### File System

```python
@pytest.fixture
def mock_pcap_read(mocker):
    mock_reader = mocker.patch("pyshark.FileCapture")
    mock_reader.return_value.__iter__ = lambda self: iter([
        MockPacket(src="192.168.1.1", dst="8.8.8.8")
    ])
    return mock_reader
```

---

## Summary

This test plan provides comprehensive coverage for all planned features:

- **Unit Tests**: 40+ test cases covering core functionality
- **Integration Tests**: 10+ test cases for component interactions
- **E2E Tests**: Full workflow validation
- **Coverage Target**: >85% overall, >90% for critical paths
- **Test Data**: Curated PCAP samples for realistic testing
