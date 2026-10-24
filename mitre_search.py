"""Semantic search API for the local MITRE ATT&CK knowledge base."""
import os
from pathlib import Path

import chromadb
import requests

BASE_DIR = Path(__file__).resolve().parent
CHROMA_DIR = Path(os.getenv("MITRE_CHROMA_DIR", BASE_DIR / "data" / "chroma"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text:latest")
COLLECTION_NAME = os.getenv("MITRE_COLLECTION", "mitre_attack")
_collection = None


def _get_collection():
    global _collection
    if _collection is None:
        client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        _collection = client.get_collection(COLLECTION_NAME)
    return _collection


def get_embedding(text):
    response = requests.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": EMBED_MODEL, "input": text},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()["embeddings"][0]


def search_mitre(query_text, n_results=3, min_similarity=0.0):
    if not isinstance(query_text, str) or not query_text.strip():
        raise ValueError("query_text must be a non-empty string")
    limit = max(1, min(int(n_results), 20))
    results = _get_collection().query(
        query_embeddings=[get_embedding(query_text.strip())],
        n_results=limit,
        include=["documents", "metadatas", "distances"],
    )
    output = []
    for technique_id, document, metadata, distance in zip(
        results["ids"][0],
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        similarity = max(-1.0, min(1.0, 1.0 - float(distance)))
        if similarity < min_similarity:
            continue
        output.append(
            {
                "id": technique_id,
                "name": metadata.get("name", ""),
                "tactics": metadata.get("tactics", ""),
                "platforms": metadata.get("platforms", ""),
                "is_subtechnique": bool(metadata.get("is_subtechnique")),
                "similarity": round(similarity, 4),
                "document": document,
            }
        )
    return output


def format_mitre_context(results):
    if not results:
        return "No relevant MITRE ATT&CK technique was found."
    return "\n".join(
        f"- {r['id']} ({r['name']}) | tactics: {r['tactics']} | similarity: {r['similarity']:.0%}"
        for r in results
    )
