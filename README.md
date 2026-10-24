# AI S.O.C

AI S.O.C is a local-first security operations demo built with Python and Flask. It brings together log and network-flow parsing, lightweight detections, an investigation dashboard, and optional local AI assistance.

## What it includes

- Parsers for Syslog, CEF, LEEF, Suricata, Windows event logs, firewall XML, NetFlow, sFlow, and PCAP input.
- Event normalization, asset context, threat-feed lookups, and heuristic checks for suspicious activity.
- Optional Splunk event streaming, configured with environment variables.
- Local Ollama analysis and MITRE ATT&CK retrieval using ChromaDB.
- A MITRE ATT&CK relationship graph, an offline CVE store, and semantic incident memory.
- A Flask API and browser dashboard, with local SQLite storage.

This project is a demonstration and research tool. Detection results need analyst review; do not rely on it as the only control in a production SOC. Review the network exposure and authentication settings before connecting it to real systems.

## Requirements

- Python 3.10 or newer
- Ollama for local language-model and embedding features
- Splunk credentials only if you enable the optional Splunk stream

Install the Python dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Configuration

Copy `.env.example` to `.env` and edit the local copy. The example contains placeholders and local defaults only.

```bash
cp .env.example .env
```

Keep Splunk usernames, passwords, session tokens, and `SOC_API_TOKEN` in `.env` or another local secret manager. Never commit `.env`. The server binds to `127.0.0.1` by default. Set a strong `SOC_API_TOKEN` before exposing the API beyond the local machine.

Splunk streaming is optional. Set `SPLUNK_HOST`, `SPLUNK_PORT`, and either `SPLUNK_SESSION_TOKEN` or `SPLUNK_USERNAME` plus `SPLUNK_PASSWORD` in your local `.env`.

## Run

Start the web application:

```bash
python soc_server.py
```

Open `http://127.0.0.1:5000` in your browser. Optional listeners and the Splunk stream should be enabled only in an authorized lab or environment.

Build the local MITRE knowledge base when using retrieval features:

```bash
ollama pull nomic-embed-text:latest
python build_mitre_rag.py --rebuild
python phase2_cli.py build-graph
python phase2_cli.py status
```

Example CLI commands:

```bash
python phase2_cli.py search-mitre "multiple failed login attempts"
python phase2_cli.py graph-query T1001 --depth 2
python phase2_cli.py import-cve /path/to/nvdcve-feed.json
python phase2_cli.py search-cve nginx --min-cvss 7
```

Generated databases and vector indexes are stored locally under `data/` and are excluded from version control. Rebuild them from the included source data and your own authorized inputs.

## Tests

```bash
python -m unittest -v test_phase2.py test_security_and_detection.py
python acceptance_phase2.py
```

## Security notes

- Use only systems, logs, packet captures, and threat feeds that you are authorized to process.
- Treat uploaded logs and PCAP files as sensitive operational data.
- Keep real credentials and environment-specific host details out of the repository.
- The bundled asset inventory and incident examples are synthetic and use documentation-safe identifiers.
