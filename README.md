# AI S.O.C — Security Operations Demo

A local-first security operations demo built with Python and Flask. It brings log and network-flow parsing, lightweight detections, an investigation dashboard, and optional local AI assistance into one project.

## Highlights

- Parse Syslog, CEF, LEEF, Suricata, Windows event logs, firewall XML, NetFlow, sFlow, and PCAP input.
- Normalize events and add asset and threat-feed context.
- Inspect suspicious activity with heuristic detections and an incident dashboard.
- Connect to Splunk for optional event streaming.
- Use local Ollama models with MITRE ATT&CK retrieval and incident memory.
- Explore MITRE ATT&CK relationships and query a local CVE store.
- Store events and investigations locally with SQLite.

## Tech stack

- Python 3.10+
- Flask and Flask-CORS
- SQLite and ChromaDB
- NetworkX
- Optional: Ollama and Splunk SDK

## Quick start

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python soc_server.py
```

Open `http://127.0.0.1:5000`.

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python soc_server.py
```

The app binds to `127.0.0.1` by default. The dashboard can run without Splunk; the Splunk stream and Ollama-backed analysis are optional integrations.

## Configure integrations

Edit your local `.env` file. Keep usernames, passwords, session tokens, and API tokens out of tracked files.

For Splunk streaming, configure `SPLUNK_HOST`, `SPLUNK_PORT`, and either `SPLUNK_SESSION_TOKEN` or `SPLUNK_USERNAME` plus `SPLUNK_PASSWORD`. Leave these empty when Splunk is not in use.

For local AI and retrieval, run Ollama and use the model names in `.env.example`. Build the local MITRE index with:

```bash
ollama pull nomic-embed-text:latest
python build_mitre_rag.py --rebuild
python phase2_cli.py build-graph
python phase2_cli.py status
```

If you enable `SOC_API_TOKEN`, enter the same value in the dashboard browser's local storage under `soc_api_token`. Keep the server bound to localhost unless you have added and tested appropriate network access controls.

## Tests

```bash
python -m unittest -v test_phase2.py test_security_and_detection.py
python acceptance_phase2.py
```

## Project structure

- `soc_server.py` — Flask API, parsers, enrichment, detections, and dashboard routes
- `soc_index.html` — browser dashboard
- `splunk_stream.py` — optional Splunk integration
- `syslog_listener.py`, `netflow_listener.py` — local event and flow listeners
- `storage.py` — SQLite event, audit, and investigation storage
- `mitre_search.py`, `mitre_graph.py`, `build_mitre_rag.py` — ATT&CK retrieval and graph tools
- `cve_store.py`, `incident_memory.py`, `phase2_cli.py` — CVE search, incident memory, and CLI
- `assets.json`, `threat_feeds.json`, `sample_incident.json` — synthetic demo data

## Responsible use

This is a demonstration and research tool. Detection results need analyst review and are not a substitute for a production SOC or other security controls. Use only systems, logs, packet captures, and threat feeds that you are authorized to process. The included asset and incident data are synthetic; local databases, indexes, credentials, and archives are excluded from version control.
