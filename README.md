# AI S.O.C — Security Operations Demo

A local-first security operations demo built with Python and Flask. It combines log and network-flow parsing, context enrichment, lightweight detections, an investigation dashboard, and optional local AI assistance.

This portfolio project was developed collaboratively with cybersecurity guidance. My implementation focus was the Python/Flask application, integrations, data flow, and analyst-facing workflow.

## Highlights

- Parse Syslog, CEF, LEEF, Suricata, Windows event logs, firewall XML, NetFlow, sFlow, and PCAP input.
- Normalize events and add asset and threat-feed context.
- Inspect suspicious activity with heuristic detections and an incident dashboard.
- Connect to Splunk for optional event streaming.
- Use local Ollama models with MITRE ATT&CK retrieval and incident memory.
- Store events and investigations locally with SQLite.

## Tech stack

- Python 3.10+
- Flask and Flask-CORS
- SQLite and ChromaDB
- NetworkX
- Optional: Ollama and Splunk SDK

## Responsible use

This is a demonstration and research tool. Detection results require analyst review and are not a substitute for a production SOC or other security controls. Use only systems, logs, packet captures, and threat feeds that you are authorized to process. Credentials, local databases, indexes, and archives must remain outside version control.
