"""Central configuration. Everything is overridable with environment variables."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "data" / "sample"
DATA_DIR = Path(os.getenv("TARA_DATA_DIR", ROOT / "data" / "runtime"))
DB_PATH = Path(os.getenv("TARA_DB_PATH", DATA_DIR / "tara.db"))
STORE_DIR = Path(os.getenv("TARA_STORE_DIR", DATA_DIR / "chroma"))

# Embeddings: "auto" tries BGE via sentence-transformers, then falls back to a local hashing embedder.
EMBED_BACKEND = os.getenv("TARA_EMBED_BACKEND", "auto")  # auto | bge | hash
EMBED_MODEL = os.getenv("TARA_EMBED_MODEL", "BAAI/bge-small-en-v1.5")

# LLM: private, local endpoint only (report requirement: no external API calls).
LLM_BACKEND = os.getenv("TARA_LLM_BACKEND", "auto")  # auto | ollama | openai | offline
LLM_BASE_URL = os.getenv("TARA_LLM_BASE_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("TARA_LLM_MODEL", "llama3.1:8b")
LLM_TEMPERATURE = float(os.getenv("TARA_LLM_TEMPERATURE", "0.1"))
LLM_TIMEOUT = float(os.getenv("TARA_LLM_TIMEOUT", "120"))

# Retrieval
TOP_K = int(os.getenv("TARA_TOP_K", "8"))
MIN_SCORE_HASH = float(os.getenv("TARA_MIN_SCORE_HASH", "0.12"))
MIN_SCORE_BGE = float(os.getenv("TARA_MIN_SCORE_BGE", "0.45"))

# Chunking (report: ~500-800 tokens with 10-15 percent overlap)
CHUNK_MAX_TOKENS = int(os.getenv("TARA_CHUNK_MAX_TOKENS", "800"))
CHUNK_OVERLAP = float(os.getenv("TARA_CHUNK_OVERLAP", "0.12"))

GLOBAL_SCOPE = "__global__"
GOVERNANCE_PRINCIPLE = (
    "AI-generated content is traceable to approved source material and reviewed by an "
    "authorised engineer before use for compliance, design approval, software release, or vehicle validation."
)
