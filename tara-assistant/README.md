# Automotive Cybersecurity TARA Assistant (Case Study 3)

An AI-assisted Threat Analysis and Risk Assessment (ISO/SAE 21434) tool built from the CS3 reference solution and the technical report.
It helps a cybersecurity engineer go from an architecture description to a cited, reviewable, traceable TARA draft.
**All output is advisory: nothing is final until an authorised engineer approves it.**

## What it does (report sections 3 to 7)

| Step | What happens | How |
|---|---|---|
| 1. Ingest | PDF / DOCX / XLSX / CSV / JSON / MD documents are cleaned (headers, duplicates, name normalisation), chunked (about 800 tokens max, 12 % overlap, one chunk per threat-library entry) and embedded | `app/knowledge.py`, ChromaDB with metadata (document, version, interface, asset tag, review date) |
| 2. Assets | Candidate assets and trust boundaries from the asset catalogue, communication matrix and architecture text, each with citations | retrieval + rules |
| 3. Attack surface | Interface-to-attack-vector mapping (CAN, Ethernet, diagnostics, OTA, backend, hardware), linked to assets and trust boundaries | `app/taxonomy.py` rules + cited evidence |
| 4. Threats | Filtered top-k retrieval from the approved threat library and prior TARA; every scenario cites its library entry; unsupported questions are flagged, not guessed | RAG, `app/agent.py` |
| 5. Risk | Impact (S/F/O/P) and attack-potential factors are proposed with rationale; **the risk value is always computed by the deterministic matrix** | `app/risk.py` |
| 6. Mitigations | Controls and requirement drafts only from the approved control catalogue, with test links | RAG + catalogue |
| 7. Review | Approve / reject / needs change per asset, threat, rating and mitigation; rationale stored; rejected items go back to recommendation | SQLite `reviews` + `audit_log` |
| 8. Traceability | Asset -> threat -> risk -> control -> test table, coverage gaps, PDF and CSV export | `app/reports.py` |

Out of scope and enforced (`app/guard.py`): writing exploits / active exploitation, and autonomous acceptance. Such requests are declined and mitigation guidance is offered instead.

## Quick start

```bash
pip install -r requirements.txt
./scripts/run_local.sh            # API on :8000, UI on http://localhost:8501
```

In the UI: **Architecture input -> Load sample TCU-Gen2 documents -> Run full TARA workflow**, then walk through the pages from the sidebar and approve or reject items.
Or follow your own path: ask *"Suggest threat scenarios for the OTA update channel of the telematics unit"* on **Threat scenarios**.

Manual start: `uvicorn app.api:app --port 8000` and `TARA_API_URL=http://localhost:8000 streamlit run ui/streamlit_app.py`.
API docs: http://localhost:8000/docs.

Docker: `docker compose up --build` (add `--profile llm` for a private Ollama container). The API and LLM live on an internal network without internet access; only the UI is published, on localhost.

## Engines: what runs where

The report specifies a privately hosted open-weight LLM and BGE embeddings. Both are pluggable and detected at start-up; the header of every result shows what was used.

| Component | Preferred | Automatic fallback |
|---|---|---|
| LLM | Local Ollama (`TARA_LLM_BASE_URL`, `TARA_LLM_MODEL`, e.g. Llama / Mistral / Qwen) or any OpenAI-compatible local server (vLLM, llama.cpp) | `offline-rules`: deterministic, library-grounded output (same schemas, no generation) |
| Embeddings | BGE via Sentence Transformers (`pip install -r requirements-bge.txt`) | local hashing embedder (no model download) |
| Vector store | ChromaDB, persistent | n/a |

With an LLM available it is used for: selecting and justifying threats from retrieved entries, proposing ratings, and wording requirements. Its output is validated: unknown ids are dropped, invalid ratings fall back to library defaults, and a risk value claimed by the model is ignored (see `tests/test_agent.py`). No external API is ever called.

## Configuration (environment variables)

`TARA_DATA_DIR` (default `data/runtime`), `TARA_LLM_BACKEND` (auto | ollama | openai | offline), `TARA_LLM_BASE_URL`, `TARA_LLM_MODEL`, `TARA_LLM_TEMPERATURE` (0.1), `TARA_EMBED_BACKEND` (auto | bge | hash), `TARA_EMBED_MODEL`, `TARA_TOP_K`, `TARA_CHUNK_MAX_TOKENS`, `TARA_CHUNK_OVERLAP`, `TARA_API_URL` (UI).

## Using your own data

Upload files on **Architecture input**. Detection:
* `.md/.txt/.pdf/.docx`: architecture description (headings such as `## Interface: OTA` set the interface metadata)
* `.csv/.xlsx` with an `asset_id` column: asset catalogue (columns: asset_id, name, tag, type, interface, properties, description, owner, version, review_date); otherwise communication matrix (message, msg_id, bus, protocol, sender, receiver, security, signals, interface)
* `.json`: approved knowledge with `doc_type` of `threat_library`, `prior_tara` or `controls` (see `data/sample/` for the schema). Rebuilt on re-upload.

The bundled threat library, control catalogue and TCU-Gen2 files are **illustrative sample data written for this pilot**, not an approved library. Replace them with your organisation's reviewed material before real use.

## Security and governance

* Role-based access: engineer (run, review), manager (adds project creation), auditor (read-only). The pilot identifies users by the `X-User` header; put the API behind SSO / a gateway for real use.
* Every run, decision, rationale, decline and export is written to the audit trail (SQLite). Knowledge entries carry owner and review date for stale-knowledge control.
* Retrieved text is treated as data in prompts, but prompt injection through uploaded documents is not fully solved; keep ingestion restricted to approved sources.
* Not yet implemented: PostgreSQL, enterprise UI, SSO, requirements/test tool integrations (the report's phases 3 to 4).

## Tests and evaluation

```bash
pip install -r requirements-dev.txt
pytest                         # 42 tests: risk matrix, guard, chunking, workflow, RBAC, LLM validation
python scripts/evaluate.py     # runs the 5 scenarios + metrics -> docs/evaluation_results.md
```

`docs/evaluation_results.md` has the measured results for report section 5. The coverage numbers are measured against an illustrative baseline for the sample data; they are not evidence of real-world coverage.

## Layout

```
app/        config, taxonomy, risk, guard, knowledge (ingest), embeddings, vectorstore, llm, db, agent, reports, api
ui/         Streamlit pilot UI
data/sample sample architecture, comm matrix, asset catalogue, threat library v1.2, prior TARA, control catalogue
tests/      pytest suite          scripts/  run_local.sh, evaluate.py          docs/  evaluation results
```
