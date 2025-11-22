# PCAP Hunter

PCAP Hunter is a comprehensive threat hunting workbench designed to analyze PCAP files using a combination of industry-standard tools (Zeek, Tshark) and modern AI (LLMs). It provides a streamlined, interactive interface for packet analysis, beaconing detection, payload carving, and OSINT enrichment, culminating in an AI-generated security report.

## Features

- **Packet Analysis**: Automated packet counting and deep flow analysis using PyShark and Tshark.
- **Zeek Integration**: Automatically runs Zeek to generate and analyze core network logs (conn, dns, http, ssl).
- **Beaconing Detection**: Identifies potential C2 (Command & Control) beaconing behavior by analyzing flow periodicity and timing.
- **Payload Carving**: Extracts HTTP file payloads for further inspection and hashing.
- **OSINT Enrichment**: Integrates with top threat intelligence APIs to enrich IP and domain data:
  - VirusTotal
  - AbuseIPDB
  - GreyNoise
  - OTX (AlienVault)
  - Shodan
- **AI-Powered Reporting**: Generates executive summaries and detailed threat reports using local LLMs (via LM Studio) or OpenAI-compatible APIs.
- **Interactive UI**: Built with [Streamlit](https://streamlit.io/) for easy visualization, configuration, and interaction.

## Installation

### Prerequisites

Ensure you have the following installed on your system:

- **Python 3.10+**
- **Zeek**: Network security monitor.
  - macOS: `brew install zeek`
  - Linux: Follow [Zeek installation guide](https://docs.zeek.org/en/master/install.html)
- **Tshark** (Wireshark): Network protocol analyzer.
  - macOS: `brew install wireshark`
  - Linux: `sudo apt install tshark`
- **LM Studio** (Optional): For running local LLMs. Download from [lmstudio.ai](https://lmstudio.ai/).

### Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd pcap-hunter
   ```

2. **Install dependencies**:
   You can use the provided `Makefile` to set up the environment:
   ```bash
   make install
   ```
   Alternatively, manually create a virtual environment and install requirements:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

1. **Start the Application**:
   ```bash
   make run
   ```
   This command activates the virtual environment and launches the Streamlit app.

2. **Upload Data**:
   - Go to the **Upload** tab.
   - Upload a `.pcap` file or specify a path to a local file.

3. **Configure Analysis**:
   - **LLM Settings**: Configure your LLM endpoint (default is local LM Studio at `http://localhost:1234/v1`).
   - **OSINT Keys**: Enter your API keys for VirusTotal, AbuseIPDB, etc., to enable enrichment.
   - **Toggles**: Enable or disable specific analysis phases (e.g., skip Zeek or Carving if not needed).

4. **Run Analysis**:
   - Click **Extract & Analyze**.
   - Switch to the **Progress** tab to watch the pipeline steps: Packet Counting -> PyShark -> Zeek -> Beaconing -> Carving -> OSINT -> Reporting.

5. **View Report**:
   - Once complete, an AI-generated report will appear, summarizing key findings, suspicious flows, and potential threats.

## Configuration

Configuration defaults are defined in `app/config.py`.
- **Data Directory**: Analysis artifacts (Zeek logs, carved files) are stored in the `data/` directory relative to the project root.
- **Limits**: Default packet limits and OSINT lookup counts can be adjusted in the UI or config file.

## Development

### Running Tests
Run the unit test suite:
```bash
make test
```

### Linting and Formatting
Check for code style issues:
```bash
make lint
```
Auto-format code:
```bash
make format
```

### Project Structure
- `app/`: Main application source code.
    - `main.py`: Streamlit entry point.
    - `pipeline/`: Core analysis logic (Zeek, PyShark, Beaconing, OSINT).
    - `ui/`: UI components and layout.
    - `llm/`: LLM client and prompt construction.
    - `utils/`: Helper functions.
- `tests/`: Unit tests.
- `data/`: Output directory for analysis artifacts (git-ignored).
