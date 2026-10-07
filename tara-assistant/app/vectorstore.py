"""ChromaDB wrapper: persistent local storage with metadata filters."""
import re
from dataclasses import dataclass

import chromadb
from chromadb.config import Settings

from . import config
from .embeddings import Embedder


@dataclass
class Hit:
    id: str
    text: str
    meta: dict
    score: float


def build_where(**conds):
    parts = []
    for k, v in conds.items():
        if v is None or v == [] or v == "":
            continue
        if isinstance(v, (list, tuple, set)):
            v = list(v)
            parts.append({k: {"$in": v}} if len(v) > 1 else {k: v[0]})
        else:
            parts.append({k: v})
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else {"$and": parts}


class VectorStore:
    def __init__(self, embedder: Embedder, path=None):
        self.embedder = embedder
        path = str(path or config.STORE_DIR)
        config.STORE_DIR.mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=path, settings=Settings(anonymized_telemetry=False))
        name = "tara_" + re.sub(r"[^a-zA-Z0-9_-]", "-", embedder.name)[:50]
        self.collection = self.client.get_or_create_collection(name=name, metadata={"hnsw:space": "cosine"}, embedding_function=None)

    def upsert(self, chunks) -> int:
        if not chunks:
            return 0
        B = 64
        for i in range(0, len(chunks), B):
            part = chunks[i:i + B]
            self.collection.upsert(
                ids=[c.id for c in part],
                documents=[c.text for c in part],
                metadatas=[c.meta for c in part],
                embeddings=self.embedder.embed([c.text for c in part]),
            )
        return len(chunks)

    def delete(self, **conds):
        where = build_where(**conds)
        if where:
            self.collection.delete(where=where)

    def count(self, **conds) -> int:
        where = build_where(**conds)
        if where is None:
            return self.collection.count()
        return len(self.collection.get(where=where, include=[])["ids"])

    def get(self, **conds) -> list[Hit]:
        res = self.collection.get(where=build_where(**conds), include=["documents", "metadatas"])
        return [Hit(i, d, m, 1.0) for i, d, m in zip(res["ids"], res["documents"], res["metadatas"])]

    def query(self, text: str, k: int = 8, **conds) -> list[Hit]:
        n = self.count(**conds)
        if n == 0:
            return []
        res = self.collection.query(
            query_embeddings=self.embedder.embed([text], is_query=True),
            n_results=min(k, n), where=build_where(**conds), include=["documents", "metadatas", "distances"],
        )
        hits = []
        for i, d, m, dist in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0]):
            hits.append(Hit(i, d, m, round(1.0 - float(dist), 4)))
        return hits
