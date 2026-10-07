import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import config  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "tara.db")
    monkeypatch.setattr(config, "STORE_DIR", tmp_path / "chroma")
    monkeypatch.setattr(config, "LLM_BACKEND", "offline")
    return tmp_path


@pytest.fixture()
def agent(env):
    from app import db
    from app.agent import TaraAgent

    a = TaraAgent()
    db.create_project("P1", "Project one", "", "engineer1")
    a.load_sample_project("P1")
    return a


@pytest.fixture()
def lib_ids():
    d = Path(config.SAMPLE_DIR)
    ids = set()
    for f in ("threat_library_v1.2.json", "prior_tara_TCU-Gen1.json"):
        ids |= {e["id"] for e in json.loads((d / f).read_text())["entries"]}
    return ids
