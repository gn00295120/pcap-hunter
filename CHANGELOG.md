# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Interactive World Map**:
    - Visualizes traffic flows with variable line thickness based on packet volume.
    - Supports cross-filtering: clicking a location or connection filters the Protocol and Flow charts.
    - Added a "Clear Selection" button to reset the dashboard view.
- **Dashboard Tab**: A new dedicated tab for high-level visualization (Map, Protocols, Flows) and the LLM Report.
- **Robust Binary Discovery**:
    - Automatically detects `tshark` and `zeek` binaries in common macOS locations (e.g., Wireshark.app, Zeek.app).
    - Added visual status indicators in the **Config** tab to show if binaries are found.
- **Runtime Logging**: A new "Runtime Logs" expander in the **Config** tab to capture and display errors during pipeline execution.
- **Unit Tests**: Added comprehensive tests for charts (`tests/test_charts.py`) and filtering logic (`tests/test_utils.py`).

### Changed
- **Performance Optimization**: Replaced `pyshark` with direct `tshark -T fields` execution for packet parsing, significantly improving speed for large PCAPs.
- **UI Refinements**:
    - Renamed "PyShark parsing" to "Parsing Packets" to reflect the backend change.
    - Renamed "Run PyShark" checkbox to "Run Packet Parsing (Tshark)".
    - Improved map prominence by increasing its height and width.
- **Configuration**:
    - Default LM Studio URL updated to `http://localhost:1234/v1`.
    - `DATA_DIR` changed to `./data` to avoid read-only file system issues.

### Fixed
- **Crash on Map Reset**: Fixed `StreamlitValueAssignmentNotAllowedError` by using a dynamic widget key for the map, ensuring clean resets.
- **Binary Detection**: Resolved issues where `tshark` and `zeek` were not found even when installed.

### [0.2.0] - 2025-11-24
### Added
- **WHOIS Lookup**:
    - Interactive WHOIS modal for IPs and Domains in the OSINT tab.
    - Displays Registrar, Dates, Registrant Info, and Name Servers in a structured layout.
    - Powered by `python-whois` with robust error handling.
- **Reverse DNS**: Added PTR record resolution for public IPs in the OSINT enrichment pipeline.
- **OSINT Tab**: Moved OSINT findings to a dedicated tab with separate views for "IP Addresses" and "Domains".
- **Zeek DNS Integration**: Automatically merges domains found in Zeek's `dns.log` into the OSINT artifacts list.

### Changed
- **UI Layout**:
    - Reorganized main tabs to include "🕵️ OSINT".
    - OSINT results now use interactive DataFrames with click-to-view functionality.
    - WHOIS dialog layout improved to stack fields vertically for better readability.

### Fixed
- **Missing Domains**: Resolved issue where domains from Zeek logs were not appearing in OSINT results.
- **IP WHOIS**: Fixed failures when querying WHOIS for IP addresses by improving the lookup logic and error handling.
