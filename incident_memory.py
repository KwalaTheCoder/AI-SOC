"""Persistent vector memory for historical SOC incidents."""
import json
import os
from pathlib import Path

import chromadb
import requests

BASE_DIR = Path(__file__).resolve().parent
CHROMA_DIR = Path(os.getenv("MITRE_CHROMA_DIR", BASE_DIR / "data" / "chroma"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text:latest")


class IncidentMemory:
    def __init__(self):
        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        self.collection = chromadb.PersistentClient(path=str(CHROMA_DIR)).get_or_create_collection(
            "incident_memory", metadata={"hnsw:space": "cosine"}
        )

    @staticmethod
    def _document(incident):
        return "\n".join(
            [
                f"Title: {incident.get('title', '')}",
                f"Description: {incident.get('description', '')}",
                f"Evidence: {json.dumps(incident.get('evidence', []), ensure_ascii=False)}",
                f"Resolution: {incident.get('resolution', '')}",
                f"MITRE: {', '.join(incident.get('mitre_ids', []))}",
            ]
        )

    @staticmethod
    def _embed(text):
        response = requests.post(
            f"{OLLAMA_URL}/api/embed",
            json={"model": EMBED_MODEL, "input": text},
            timeout=60,
        )
        response.raise_for_status()
        return response.json()["embeddings"][0]

    def add(self, incident):
        incident_id = str(incident.get("id", "")).strip()
        if not incident_id:
            raise ValueError("incident.id is required")
        document = self._document(incident)
        metadata = {
            "title": str(incident.get("title", "")),
            "priority": str(incident.get("priority", "")),
            "status": str(incident.get("status", "")),
            "created_at": str(incident.get("created_at", "")),
        }
        self.collection.upsert(
            ids=[incident_id], documents=[document], metadatas=[metadata],
            embeddings=[self._embed(document)]
        )
        return incident_id

    def search(self, query, limit=5):
        result = self.collection.query(
            query_embeddings=[self._embed(query)], n_results=max(1, min(int(limit), 20)),
            include=["documents", "metadatas", "distances"],
        )
        return [
            {
                "id": incident_id,
                "similarity": round(1 - float(distance), 4),
                "metadata": metadata,
                "document": document,
            }
            for incident_id, distance, metadata, document in zip(
                result["ids"][0], result["distances"][0],
                result["metadatas"][0], result["documents"][0]
            )
        ]
