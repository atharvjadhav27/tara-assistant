"""Embedding backends.

* BGE via Sentence Transformers (target model from the report) when the package and model are available locally.
* HashingEmbedder: a dependency-light, fully offline fallback (word and bigram hashing) so the pilot runs anywhere.
"""
import logging
import re
from typing import Protocol

import numpy as np

from . import config

log = logging.getLogger("tara.embeddings")


class Embedder(Protocol):
    name: str
    min_score: float

    def embed(self, texts: list[str], is_query: bool = False) -> list[list[float]]: ...


def _stop_words():
    from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

    # keep domain words that the generic list would drop ("can" = CAN bus, "bus", "system", "access", "update")
    return sorted(set(ENGLISH_STOP_WORDS) - {"can", "bus", "system", "access", "update", "interest", "front", "back"})


class HashingEmbedder:
    DIM = 2048

    def __init__(self):
        from sklearn.feature_extraction.text import HashingVectorizer

        self.name = f"hash-{self.DIM}"
        self.min_score = config.MIN_SCORE_HASH
        self._vec = HashingVectorizer(
            n_features=self.DIM, alternate_sign=False, norm="l2", ngram_range=(1, 2),
            stop_words=_stop_words(), token_pattern=r"(?u)\b[\w\-]{2,}\b", lowercase=True,
        )

    @staticmethod
    def _prep(t: str) -> str:
        # split identifiers like TL-OTA-03 / SOME/IP into parts so that partial matches count
        from .taxonomy import normalise_names

        return normalise_names(re.sub(r"[/_]", " ", t))

    def embed(self, texts, is_query=False):
        m = self._vec.transform([self._prep(t) for t in texts])
        return m.toarray().astype(float).tolist()


class BGEEmbedder:
    def __init__(self, model_name: str):
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)
        self.name = model_name.split("/")[-1].lower()
        self.min_score = config.MIN_SCORE_BGE

    def embed(self, texts, is_query=False):
        if is_query:  # BGE retrieval instruction
            texts = ["Represent this sentence for searching relevant passages: " + t for t in texts]
        return self._model.encode(texts, normalize_embeddings=True).tolist()


_cached: Embedder | None = None


def get_embedder() -> Embedder:
    global _cached
    if _cached is not None:
        return _cached
    choice = config.EMBED_BACKEND
    if choice in ("auto", "bge"):
        try:
            _cached = BGEEmbedder(config.EMBED_MODEL)
            log.info("Using BGE embedder %s", config.EMBED_MODEL)
            return _cached
        except Exception as exc:  # package missing, model not cached, no network
            if choice == "bge":
                raise
            log.warning("BGE unavailable (%s); falling back to hashing embedder", type(exc).__name__)
    _cached = HashingEmbedder()
    return _cached


def reset_embedder():
    global _cached
    _cached = None
