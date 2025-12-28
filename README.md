# PCAP Hunter

**PCAP Hunter** is an advanced, AI-enhanced threat hunting workbench designed to bridge the gap between manual packet analysis and automated security monitoring. It empowers SOC analysts and threat hunters to rapidly ingest, analyze, and extract actionable intelligence from raw PCAP files.

By combining industry-standard network analysis tools (**Zeek**, **Tshark**) with modern **Large Language Models (LLMs)** and **OSINT** APIs, PCAP Hunter automates the tedious parts of packet analysis—parsing, correlation, and enrichment—allowing analysts to focus on detection and response.

---

## 🚀 Key Features

### 1. 🧠 AI-Powered Threat Analysis
- **Automated Reporting**: Generates professional, SOC-ready reports summarizing key findings, suspicious indicators, and risk assessments.
- **Local & Cloud LLM Support**:
  - **Local Privacy**: Fully compatible with local models via [LM Studio](https://lmstudio.ai/) (e.g., Llama 3, Mistral) for air-gapped or privacy-sensitive analysis.
  - **Cloud Power**: Supports OpenAI-compatible APIs for leveraging larger models like GPT-4.
- **Context-Aware**: The AI is fed a structured summary of network flows, Zeek logs, and OSINT data, acting as an expert co-pilot.

### 2. 🔍 Deep Packet Inspection & Flow Analysis
- **Multi-Engine Pipeline**: Uses **PyShark** for granular packet inspection and **Tshark** for high-speed statistics.
- **Protocol Parsing**: Automatically extracts and visualizes metadata for major protocols:
  - **HTTP**: Methods, URIs, User-Agents.
  - **DNS**: Queries, responses, record types.
  - **TLS/SSL**: Server names (SNI), certificate details.
  - **SMB**: File shares and commands.

### 3. 🛡️ Zeek Integration
- **Automated Lifecycle**: Manages the execution of Zeek on uploaded PCAPs without requiring manual command-line intervention.
- **Log Analysis**: Parses and correlates core Zeek logs into interactive data tables:
  - `conn.log`: Connection summaries and state.
  - `dns.log`: Name resolution activity.
  - `http.log`: Web traffic details.
  - `ssl.log`: Encrypted traffic metadata.

### 4. 📡 C2 Beaconing Detection
- **Heuristic Analysis**: Implements a statistical algorithm to detect Command & Control (C2) beaconing behavior.
- **Scoring Engine**: Ranks flows based on:
  - **Periodicity**: Regularity of communication intervals (low variance).
  - **Jitter**: Randomization attempts by C2 agents.
  - **Volume**: Consistency of payload sizes.

### 5. 📦 Payload Carving & Forensics
- **File Extraction**: Uses `tshark` to carve HTTP file bodies from the traffic.
- **Artifact Hashing**: Automatically calculates SHA256 hashes of extracted files for reputation checking.
- **Safe Storage**: Carved files are stored locally in a quarantined directory for manual analysis.

### 6. 🌍 Interactive World Map & Dashboard
- **Global Visibility**: Visualizes traffic sources and destinations on a large, interactive world map.
- **Traffic Volume**: Line thickness varies based on connection volume, highlighting major data flows.
- **Cross-Filtering**:
  - **Unified Drill-Down**: Selecting data in any chart (Map, Pie, or Timeline) filters the entire dashboard.
  - **Protocol Filter**: Click a slice in the Protocol Pie Chart to isolate that protocol.
  - **Time Filter**: Select a range on the Flow Timeline to focus on a specific time window.
- **Reset Capability**: Includes a "Clear All Filters" button to easily reset the dashboard view.

### 7. 🌐 OSINT Enrichment
Integrates with leading threat intelligence providers to validate indicators of compromise (IOCs):
- **VirusTotal**: File hash and IP/Domain reputation.
- **AbuseIPDB**: Crowdsourced IP abuse reports.
- **GreyNoise**: Identification of internet background noise and scanners.
- **OTX (AlienVault)**: Open Threat Exchange pulses and indicators.
- **Shodan**: Internet-facing device details and open ports.

---

## 🛠️ Installation

### Prerequisites
- **Python 3.10+**
- **Zeek**: `brew install zeek` (macOS) or via package manager (Linux).
- **Tshark**: `brew install wireshark` (macOS) or `sudo apt install tshark` (Linux).
- **LM Studio** (Optional): For local LLM inference.

### Quick Start
1. **Clone the repo**:
   ```bash
   git clone https://github.com/ninedter/pcap-hunter.git
   cd pcap-hunter
   ```
2. **Install dependencies**:
   ```bash
   make install
   ```
3. **Run the application**:
   ```bash
   make run
   ```

---

## 📖 Usage Guide

1. **Upload**: Drag and drop a `.pcap` file in the **Upload** tab.
2. **Configure**:
   - Set your LLM endpoint (default: `http://localhost:1234/v1`).
   - Add API keys for OSINT services (optional but recommended).
   - Toggle specific analysis phases (e.g., disable "Carving" for faster processing).
3. **Analyze**: Click **Extract & Analyze**.
4. **Monitor**: Watch the **Progress** tab as the pipeline executes:
   - *Packet Counting* -> *Parsing* -> *Zeek* -> *Beaconing* -> *Carving* -> *OSINT* -> *Reporting*.
5. **Review**: Read the generated **Threat Report** and explore the raw data tables for deep dives.

---

## ⚙️ Configuration
Defaults are managed in `app/config.py`. Key settings include:
- `DATA_DIR`: Location for storing analysis artifacts (default: `./data`).
- `DEFAULT_PYSHARK_LIMIT`: Max packets to parse deeply (default: 200,000).
- `OSINT_TOP_IPS_DEFAULT`: Number of top talkers to enrich (default: 50).

## 🧑‍💻 Development
- **Test**: `make test`
- **Lint**: `make lint`
- **Format**: `make format`
- **Clean**: `make clean`

## 📄 License
MIT License. See `LICENSE` for details.
