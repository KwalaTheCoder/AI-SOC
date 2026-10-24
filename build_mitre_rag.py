"""Build the local MITRE ATT&CK vector knowledge base."""
import argparse
import json
import os
import time
from pathlib import Path

import chromadb
import requests

BASE_DIR = Path(__file__).resolve().parent
MITRE_FILE = Path(os.getenv("MITRE_FILE", BASE_DIR / "mitre_techniques.json"))
CHROMA_DIR = Path(os.getenv("MITRE_CHROMA_DIR", BASE_DIR / "data" / "chroma"))
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text:latest")
COLLECTION_NAME = os.getenv("MITRE_COLLECTION", "mitre_attack")


def embed_batch(texts, timeout=120):
    response = requests.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": EMBED_MODEL, "input": texts},
        timeout=timeout,
    )
    response.raise_for_status()
    vectors = response.json().get("embeddings", [])
    if len(vectors) != len(texts):
        raise RuntimeError(f"Ollama returned {len(vectors)} vectors for {len(texts)} documents")
    return vectors


def document_text(technique):
    return "\n".join(
        [
            f"{technique['id']} - {technique['name']}",
            f"Tactics: {', '.join(technique.get('tactics', [])) or 'Unknown'}",
            f"Platforms: {', '.join(technique.get('platforms', [])) or 'Unknown'}",
            f"Description: {technique.get('description', '')}",
            f"Detection: {technique.get('detection', '')}",
        ]
    )


def build(batch_size=32, rebuild=False):
    techniques = json.loads(MITRE_FILE.read_text(encoding="utf-8"))
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    if rebuild:
        try:
            client.delete_collection(COLLECTION_NAME)
        except Exception:
            pass
    collection = client.get_or_create_collection(
        COLLECTION_NAME,
        metadata={"description": "MITRE ATT&CK Enterprise", "hnsw:space": "cosine"},
    )
    started = time.time()
    for offset in range(0, len(techniques), batch_size):
        batch = techniques[offset : offset + batch_size]
        docs = [document_text(item) for item in batch]
        vectors = embed_batch(docs)
        collection.upsert(
            ids=[item["id"] for item in batch],
            documents=docs,
            embeddings=vectors,
            metadatas=[
                {
                    "name": item["name"],
                    "tactics": ", ".join(item.get("tactics", [])),
                    "platforms": ", ".join(item.get("platforms", [])),
                    "is_subtechnique": bool(item.get("is_subtechnique")),
                }
                for item in batch
            ],
        )
        print(f"{min(offset + batch_size, len(techniques))}/{len(techniques)}")
    result = {
        "collection": COLLECTION_NAME,
        "records": collection.count(),
        "model": EMBED_MODEL,
        "path": str(CHROMA_DIR),
        "elapsed_seconds": round(time.time() - started, 2),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--rebuild", action="store_true")
    args = parser.parse_args()
    build(max(1, args.batch_size), args.rebuild)
