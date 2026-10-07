"""Step-wise TARA agent: assets -> attack surface -> threats -> risk -> mitigations -> review -> traceability.

Design rules (from the report):
* every recommendation carries source citations drawn from retrieved, approved material
* the LLM may only *select / propose / word*; ids are validated against retrieved context
* the risk value is always computed by the deterministic matrix (risk.py)
* answers without supporting context are flagged, not guessed
* everything is advisory and stored as 'pending' until an authorised engineer decides
"""
import json
import re
import time
from functools import wraps

from . import config, db, risk
from .embeddings import get_embedder
from .guard import check_scope
from .knowledge import ingest
from .llm import SYSTEM_PROMPT, LLMClient
from .taxonomy import INTERFACES, SURFACE_RULES, detect_interfaces
from .vectorstore import Hit, VectorStore

WORKFLOW_ORDER = ["OTA", "DIAG", "CAN", "ETH", "BACKEND", "HW"]
SAMPLE_GLOBAL = ["threat_library_v1.2.json", "prior_tara_TCU-Gen1.json", "control_catalogue_v1.0.json"]
SAMPLE_PROJECT = ["architecture_TCU-Gen2.md", "communication_matrix_TCU-Gen2.csv", "asset_catalogue_TCU-Gen2.csv"]
THREAT_KINDS = ["threat_library", "prior_tara"]
TB_BY_IFACE = {"DIAG": "TB-2", "BACKEND": "TB-1", "OTA": "TB-1", "CAN": "TB-3", "ETH": "TB-3", "HW": "TB-4"}
DERIVED_ASSETS = {  # asset tags that can be derived from the communication matrix when the catalogue lacks them
    "can_signals": ("CAN signals", "CAN", "Signal"),
    "eth_services": ("Ethernet service data (SOME/IP)", "ETH", "Data"),
    "diag_access": ("Diagnostic access", "DIAG", "Interface"),
    "backend_link": ("Backend link", "BACKEND", "Communication channel"),
}


class AgentError(Exception):
    def __init__(self, message, code=400):
        super().__init__(message)
        self.code = code


def timed(step):
    def deco(fn):
        @wraps(fn)
        def wrapper(self, project_id, *a, **kw):
            t0 = time.perf_counter()
            res = fn(self, project_id, *a, **kw)
            ms = (time.perf_counter() - t0) * 1000
            db.record_run(project_id, step, ms, self.llm.engine)
            return res
        return wrapper
    return deco


class TaraAgent:
    def __init__(self, store: VectorStore | None = None, llm: LLMClient | None = None):
        self.embedder = get_embedder()
        self.store = store or VectorStore(self.embedder)
        self.llm = llm or LLMClient()
        db.init_db()

    # ------------------------------------------------------------ knowledge
    def ensure_global_knowledge(self):
        if self.store.count(project=config.GLOBAL_SCOPE) == 0:
            for f in SAMPLE_GLOBAL:
                ingest(self.store, f, (config.SAMPLE_DIR / f).read_bytes(), config.GLOBAL_SCOPE)

    def ingest_bytes(self, project_id, name, data, doc_type=None, user="system"):
        rec = ingest(self.store, name, data, project_id, doc_type)
        db.add_document_log(project_id, rec)
        db.audit(user, project_id, "ingest_document", rec["document"], {k: rec[k] for k in ("doc_type", "n_chunks", "sha256")})
        return rec

    def load_sample_project(self, project_id, user="system"):
        self.ensure_global_knowledge()
        return [self.ingest_bytes(project_id, f, (config.SAMPLE_DIR / f).read_bytes(), user=user) for f in SAMPLE_PROJECT]

    def search(self, query, scope, kinds=None, interfaces=None, k=None, asset_tag=None) -> list[Hit]:
        """Filtered top-k retrieval. When a metadata filter already scopes the search (interface), the similarity
        threshold is relaxed because the filter itself is evidence of relevance; unfiltered queries need a clear match."""
        hits = self.store.query(query, k or config.TOP_K, project=scope, doc_type=kinds, interface=interfaces, asset_tag=asset_tag)
        floor = self.embedder.min_score * (0.05 if interfaces else 1.0)
        return [h for h in hits if h.score >= floor]

    def _entry(self, library_id):
        hits = self.store.get(project=config.GLOBAL_SCOPE, record_id=library_id)
        hits = [h for h in hits if h.meta.get("entry_json") and h.meta["doc_type"] in THREAT_KINDS]
        return json.loads(hits[0].meta["entry_json"]) if hits else None

    def _controls(self, ids):
        out = {}
        for h in self.store.get(project=config.GLOBAL_SCOPE, doc_type="controls", record_id=list(ids)):
            out[h.meta["record_id"]] = (json.loads(h.meta["entry_json"]), h.meta["citation"])
        return out

    def project_interfaces(self, project_id) -> list[str]:
        hs = self.store.get(project=project_id)
        return sorted({h.meta["interface"] for h in hs if h.meta["interface"] not in ("", "GENERAL")})

    def _require_docs(self, project_id):
        if not db.get_project(project_id):
            raise AgentError("Unknown project", 404)
        if self.store.count(project=project_id) == 0:
            raise AgentError("No project documents ingested yet. Add architecture input first.", 409)

    # ------------------------------------------------------------ step 1-2: assets
    @timed("identify_assets")
    def identify_assets(self, project_id, user="system") -> dict:
        self._require_docs(project_id)
        ifaces = set(self.project_interfaces(project_id))
        assets, seen_tags = [], set()
        for h in self.store.get(project=project_id, doc_type="asset_catalogue"):
            m = h.meta
            if m["interface"] not in ifaces:  # no architecture / matrix evidence for this interface
                continue
            ev = self.search(f"{m['asset_name']} {m['description']}", project_id, ["architecture", "comm_matrix"], [m["interface"]], k=2)
            assets.append({"asset_id": m["record_id"], "name": m["asset_name"], "tag": m["asset_tag"], "type": m["asset_type"],
                           "interface": m["interface"], "properties": m["properties"], "description": m["description"], "owner": m["owner"],
                           "origin": "asset catalogue", "citations": [m["citation"]] + [e.meta["citation"] for e in ev]})
            seen_tags.add(m["asset_tag"])
        n = len(assets)
        for tag, (name, iface, typ) in DERIVED_ASSETS.items():  # derived from the communication matrix
            if tag in seen_tags or iface not in ifaces:
                continue
            rows = self.store.get(project=project_id, doc_type="comm_matrix", interface=iface)
            if rows:
                n += 1
                assets.append({"asset_id": f"A-D{n}", "name": name, "tag": tag, "type": typ, "interface": iface, "properties": "",
                               "description": f"Derived from {len(rows)} communication-matrix rows on the {INTERFACES[iface]} interface.",
                               "owner": "", "origin": "derived from communication matrix", "citations": [r.meta["citation"] for r in rows[:3]]})
        # trust boundaries from the architecture description
        boundaries = []
        for h in self.store.get(project=project_id, doc_type="architecture"):
            if "trust boundar" in h.meta.get("section", "").lower():
                for m in re.finditer(r"(?:Boundary\s+)?(TB-\d+):\s*([^\n]+)", h.text):
                    boundaries.append({"boundary_id": m.group(1), "description": m.group(2).strip(), "citations": [h.meta["citation"]]})
        for a in assets:
            db.upsert_item(project_id, "asset", a["asset_id"], a, engine="rules+retrieval")
        for b in boundaries:
            db.upsert_item(project_id, "boundary", b["boundary_id"], b, engine="rules+retrieval")
        db.audit(user, project_id, "identify_assets", detail={"assets": len(assets), "boundaries": len(boundaries)})
        return {"assets": db.get_items(project_id, "asset"), "boundaries": db.get_items(project_id, "boundary")}

    # ------------------------------------------------------------ step 3: attack surface
    @timed("map_attack_surface")
    def map_attack_surface(self, project_id, interfaces=None, user="system") -> list[dict]:
        self._require_docs(project_id)
        if not db.get_items(project_id, "asset"):
            self.identify_assets(project_id, user)
        assets = [a["data"] for a in db.get_items(project_id, "asset")]
        boundary_ids = {b["ref"] for b in db.get_items(project_id, "boundary")}
        present = set(self.project_interfaces(project_id))
        todo = [i for i in (interfaces or list(SURFACE_RULES)) if i in present]
        for iface in todo:
            for n, rule in enumerate(SURFACE_RULES[iface], 1):
                ev = self.search(f"{rule['entry_point']} {rule['vector']}", project_id, ["architecture", "comm_matrix"], [iface], k=3)
                linked = [a for a in assets if a["tag"] in rule["asset_tags"]]
                tb = TB_BY_IFACE.get(iface)
                data = {"interface": iface, "interface_name": INTERFACES[iface], "entry_point": rule["entry_point"], "vector": rule["vector"],
                        "exposure": rule["exposure"], "asset_ids": [a["asset_id"] for a in linked], "asset_names": [a["name"] for a in linked],
                        "trust_boundary": tb if tb in boundary_ids else "", "citations": [e.meta["citation"] for e in ev]}
                if not ev:
                    data["warning"] = "No supporting passage found in project documents"
                db.upsert_item(project_id, "surface", f"AS-{iface}-{n}", data, engine="rules+retrieval")
        db.audit(user, project_id, "map_attack_surface", detail={"interfaces": todo})
        return db.get_items(project_id, "surface")

    # ------------------------------------------------------------ step 4: threats (RAG)
    @timed("recommend_threats")
    def recommend_threats(self, project_id, query, interfaces=None, top_k=None, user="system") -> dict:
        guard = check_scope(query)
        if not guard["allowed"]:
            db.audit(user, project_id, "request_declined", detail={"reason": guard["reason"], "query": query[:200]})
            return {"status": "declined", "reason": guard["reason"], "message": guard["message"], "engine": self.llm.engine,
                    "mitigation_guidance": self._mitigation_guidance(query, project_id)}
        self._require_docs(project_id)
        if not db.get_items(project_id, "asset"):
            self.identify_assets(project_id, user)
        ifaces = interfaces or detect_interfaces(query) or None
        hits = self.search(query, config.GLOBAL_SCOPE, THREAT_KINDS, ifaces, k=top_k or config.TOP_K)
        if not hits:
            msg = "No approved threat-library or prior-TARA entry supports this request, so no recommendation was made."
            db.audit(user, project_id, "insufficient_context", detail={"query": query[:200]})
            return {"status": "insufficient_context", "message": msg, "threats": [], "engine": self.llm.engine}

        selected, engine = self._select_threats(query, hits)
        assets = [a["data"] for a in db.get_items(project_id, "asset")]
        out = []
        for h, sel in selected:
            e = json.loads(h.meta["entry_json"])
            linked = [a for a in assets if a["tag"] == e["asset_tag"]]
            ex = next((i for i in db.get_items(project_id, "threat") if i["data"]["library_id"] == e["id"]), None)
            ref = ex["ref"] if ex else db.next_ref(project_id, "threat", "T")
            prelim = risk.compute(e["impact"], e["feasibility"])
            data = {"library_id": e["id"], "title": e["title"], "description": e["description"], "interface": e["interface"],
                    "asset_tag": e["asset_tag"], "asset_ids": [a["asset_id"] for a in linked], "asset_names": [a["name"] for a in linked],
                    "stride": e["stride"], "attack_vector": e["attack_vector"], "damage_scenario": e["damage_scenario"],
                    "citation": h.meta["citation"], "retrieval_score": h.score, "rationale": sel["rationale"],
                    "assumptions": sel["assumptions"], "alternatives": sel["alternatives"], "proposed_risk": prelim["risk_label"],
                    "query": query}
            if not linked:
                data["warning"] = "No matching asset identified in this project; confirm applicability before approving."
            iid = db.upsert_item(project_id, "threat", ref, data, engine=engine)
            out.append(db.get_item_by_id(project_id, iid))
        db.audit(user, project_id, "recommend_threats", detail={"query": query[:200], "returned": [t["data"]["library_id"] for t in out], "engine": engine})
        return {"status": "ok", "engine": engine, "threats": out, "message": "AI suggestions only; pending engineer review."}

    def _select_threats(self, query, hits):
        """LLM selects and justifies from retrieved entries; ids are validated. Offline: rules + library rationale."""
        by_id = {h.meta["record_id"]: h for h in hits}
        if self.llm.available:
            ctx = [{"id": h.meta["record_id"], "text": h.text} for h in hits]
            res = self.llm.complete_json(SYSTEM_PROMPT, json.dumps({
                "task": "From CONTEXT choose the threat scenarios that answer the QUERY. Return {\"selected\":[{\"id\",\"rationale\",\"assumptions\":[],\"alternatives\":[]}]}. Use only ids in CONTEXT.",
                "query": query, "context": ctx}))
            sel = []
            for s in (res or {}).get("selected", []) if isinstance(res, dict) else []:
                if isinstance(s, dict) and s.get("id") in by_id and s.get("rationale"):
                    e = json.loads(by_id[s["id"]].meta["entry_json"])
                    sel.append((by_id[s["id"]], {"rationale": str(s["rationale"]), "assumptions": [str(x) for x in s.get("assumptions", [])] or e["assumptions"] or self._default_assumptions(),
                                                 "alternatives": [str(x) for x in s.get("alternatives", [])] or e["alternatives"] or self._default_alternatives()}))
            if sel:
                return sel, self.llm.engine
        sel = []
        for h in hits:
            e = json.loads(h.meta["entry_json"])
            sel.append((h, {"rationale": f"{e['rationale']} Matches the request on the {INTERFACES.get(e['interface'], e['interface'])} interface (STRIDE: {e['stride']}).",
                            "assumptions": e["assumptions"] or self._default_assumptions(),
                            "alternatives": e["alternatives"] or self._default_alternatives()}))
        return sel, "offline-rules"

    @staticmethod
    def _default_assumptions():
        return ["The approved library entry applies to this architecture as documented; the engineer must confirm the interface is exposed."]

    @staticmethod
    def _default_alternatives():
        return ["Reject if the interface is isolated or the asset is not present in this system; consider a more specific library entry."]

    def _mitigation_guidance(self, query, project_id):
        """Offered instead of exploit help: controls for the named interface, else baseline controls per project interface."""
        ifaces = detect_interfaces(query)
        hits = self.search(query + " mitigation control", config.GLOBAL_SCOPE, ["controls"], ifaces or None, k=3)
        if not hits:
            present = set(self.project_interfaces(project_id)) if project_id and db.get_project(project_id) else set(WORKFLOW_ORDER)
            for iface in [i for i in WORKFLOW_ORDER if i in present]:
                hits += self.search("authentication integrity protection control", config.GLOBAL_SCOPE, ["controls"], [iface], k=1)
        return [{"control_id": h.meta["record_id"], "title": h.meta["title"], "citation": h.meta["citation"],
                 "requirement": json.loads(h.meta["entry_json"])["requirement"]} for h in hits]

    # ------------------------------------------------------------ step 5: risk
    @timed("assess_risk")
    def assess_risk(self, project_id, threat_ref, user="system") -> dict:
        t = db.get_item(project_id, "threat", threat_ref)
        if not t:
            raise AgentError("Unknown threat", 404)
        e = self._entry(t["data"]["library_id"])
        if not e:
            raise AgentError("Approved library entry not found; cannot assess without a source.", 409)
        ev = self.search(f"{e['title']} {e['attack_vector']}", project_id, ["architecture", "comm_matrix"], [e["interface"]], k=3)
        rows = self.store.get(project=project_id, doc_type="comm_matrix", interface=e["interface"])
        unauth = [r for r in rows if r.text.lower().count("security: none")]
        evidence = ""
        if rows:
            evidence = (f" Project evidence: {len(rows)} communication-matrix rows on this interface, {len(unauth)} without message security.")
        impact, factors, rationale, source, engine = e["impact"], e["feasibility"], e["rationale"], "approved library defaults", "offline-rules"
        prior = db.get_item(project_id, "rating", f"R-{threat_ref}")
        comment = ""
        if prior and prior["status"] == "needs_change":
            rv = db.get_reviews(prior["id"])
            comment = rv[-1]["rationale"] if rv else ""
        if self.llm.available:
            res = self.llm.complete_json(SYSTEM_PROMPT, json.dumps({
                "task": "Propose impact ratings (safety, financial, operational, privacy) and attack-potential factors for this threat, with a short rationale. "
                        "Return {\"impact\":{...},\"factors\":{...},\"rationale\":\"...\"}.",
                "allowed": {"impact": risk.IMPACT_LEVELS, "factors": {k: list(v) for k, v in risk.FACTORS.items()}},
                "threat": {k: e[k] for k in ("id", "title", "description", "attack_vector", "damage_scenario")},
                "library_defaults": {"impact": e["impact"], "factors": e["feasibility"]},
                "project_context": [{"id": h.meta["citation"], "text": h.text} for h in ev], "reviewer_comment": comment}))
            try:
                if isinstance(res, dict):
                    risk.compute(res["impact"], res["factors"])  # schema validation
                    if res.get("rationale"):
                        impact, factors, rationale, source, engine = res["impact"], res["factors"], str(res["rationale"]), "LLM proposal", self.llm.engine
            except (KeyError, risk.RiskInputError, TypeError):
                pass
        calc = risk.compute(impact, factors)  # deterministic matrix: final risk value
        if comment:
            rationale += f" Reviewer comment considered: {comment}"
        data = {"threat_ref": threat_ref, "library_id": e["id"], "title": t["data"]["title"], "impact": impact, "factors": factors, **calc,
                "rationale": rationale + evidence, "rating_source": source, "sources": [t["data"]["citation"]] + [h.meta["citation"] for h in ev],
                "approval_state": "Pending human approval", "matrix_version": "ISO/SAE 21434 Annex H style matrix"}
        db.upsert_item(project_id, "rating", f"R-{threat_ref}", data, parent_ref=threat_ref, engine=engine, keep_status=False)
        db.audit(user, project_id, "assess_risk", threat_ref, {"risk": calc["risk_label"], "engine": engine})
        return db.get_item(project_id, "rating", f"R-{threat_ref}")

    # ------------------------------------------------------------ step 6: mitigations
    @timed("recommend_mitigations")
    def recommend_mitigations(self, project_id, threat_ref, user="system") -> list[dict]:
        t = db.get_item(project_id, "threat", threat_ref)
        if not t:
            raise AgentError("Unknown threat", 404)
        e = self._entry(t["data"]["library_id"])
        if not e:
            raise AgentError("Approved library entry not found.", 409)
        ctrls = self._controls(e["controls"])
        extra = [h for h in self.search(f"{e['title']} {e['attack_vector']}", config.GLOBAL_SCOPE, ["controls"], [e["interface"]], k=4)
                 if h.meta["record_id"] not in ctrls][:2]
        alts = [{"control_id": h.meta["record_id"], "title": h.meta["title"], "citation": h.meta["citation"]} for h in extra]
        asset_txt = ", ".join(t["data"]["asset_names"]) or "the affected asset"
        out = []
        for n, cid in enumerate(e["controls"], 1):
            if cid not in ctrls:
                continue  # never recommend a control that is not in the approved catalogue
            c, cite = ctrls[cid]
            req, engine = f"{c['requirement']} (Applies to: {asset_txt}.)", "offline-rules"
            if self.llm.available:
                res = self.llm.complete_json(SYSTEM_PROMPT, json.dumps({
                    "task": "Rewrite the control requirement as one precise, verifiable requirement for this threat. Keep its meaning. Return {\"requirement\":\"...\"}.",
                    "threat": {k: e[k] for k in ("id", "title", "description")}, "asset": asset_txt, "control": c}))
                if isinstance(res, dict) and isinstance(res.get("requirement"), str) and len(res["requirement"]) > 20:
                    req, engine = res["requirement"].strip(), self.llm.engine
            data = {"threat_ref": threat_ref, "library_id": e["id"], "control_id": cid, "title": c["title"], "requirement_id": f"REQ-{threat_ref}-{n}",
                    "requirement": req, "cybersecurity_goal": c["cybersecurity_goal"], "test_ids": c["test_ids"], "citation": cite,
                    "assumptions": ["Control applicability and strength must be confirmed against the TCU design by the engineer."],
                    "alternatives": alts}
            iid = db.upsert_item(project_id, "mitigation", f"M-{threat_ref}-{cid}", data, parent_ref=threat_ref, engine=engine, keep_status=False)
            out.append(db.get_item_by_id(project_id, iid))
        db.audit(user, project_id, "recommend_mitigations", threat_ref, {"controls": [m["data"]["control_id"] for m in out]})
        return out

    # ------------------------------------------------------------ step 7: review
    def review_item(self, project_id, item_id, user, decision, rationale="") -> dict:
        it = db.get_item_by_id(project_id, item_id)
        if not it:
            raise AgentError("Unknown item", 404)
        if decision not in ("approve", "reject", "needs_change"):
            raise AgentError("decision must be approve, reject or needs_change")
        if decision != "approve" and not rationale.strip():
            raise AgentError("A rationale is required to reject an item or request changes.")
        status = db.add_review(item_id, user, decision, rationale.strip() or "Approved as proposed")
        db.audit(user, project_id, f"review_{decision}", f"{it['kind']}:{it['ref']}", {"rationale": rationale, "status": status})
        return db.get_item_by_id(project_id, item_id)

    def regenerate(self, project_id, item_id, user="system"):
        """Rejected / needs-change items go back to recommendation."""
        it = db.get_item_by_id(project_id, item_id)
        if not it:
            raise AgentError("Unknown item", 404)
        if it["kind"] == "rating":
            return self.assess_risk(project_id, it["parent_ref"], user)
        if it["kind"] == "mitigation":
            return self.recommend_mitigations(project_id, it["parent_ref"], user)
        raise AgentError("Only ratings and mitigations can be regenerated; re-run the step for other items.")

    # ------------------------------------------------------------ step 8: traceability
    def traceability(self, project_id, include_rejected=False) -> dict:
        threats = db.get_items(project_id, "threat")
        ratings = {r["parent_ref"]: r for r in db.get_items(project_id, "rating")}
        mits = db.get_items(project_id, "mitigation")
        assets = db.get_items(project_id, "asset")
        rows, covered_assets = [], set()
        for t in threats:
            if t["status"] == "rejected" and not include_rejected:
                continue
            d = t["data"]
            r = ratings.get(t["ref"])
            ms = [m for m in mits if m["parent_ref"] == t["ref"] and (include_rejected or m["status"] != "rejected")]
            covered_assets.update(d["asset_ids"])
            rows.append({
                "asset": ", ".join(d["asset_names"]) or "(no matching asset)", "asset_ids": d["asset_ids"],
                "threat_ref": t["ref"], "threat": f"{t['ref']} {d['title']}", "library_id": d["library_id"],
                "risk": r["data"]["risk_label"] if r else f"{d['proposed_risk']} (preliminary)", "risk_value": r["data"]["risk_value"] if r else None,
                "controls": [f"{m['data']['title']} ({m['data']['control_id']})" for m in ms],
                "requirements": [m["data"]["requirement_id"] for m in ms],
                "tests": sorted({tid for m in ms for tid in m["data"]["test_ids"]}),
                "status": {"threat": t["status"], "rating": r["status"] if r else "not assessed",
                           "mitigations": sorted({m["status"] for m in ms}) or ["none"]},
                "citations": [d["citation"]] + ([c for c in r["data"]["sources"][1:]] if r else []),
            })
        gaps = []
        for a in assets:
            if a["ref"] not in covered_assets:
                gaps.append(f"Asset {a['ref']} {a['data']['name']} has no threat scenario yet.")
        for row in rows:
            if row["risk_value"] is None:
                gaps.append(f"{row['threat_ref']} has no risk assessment.")
            if not row["controls"]:
                gaps.append(f"{row['threat_ref']} has no mitigation / requirement.")
        return {"project_id": project_id, "rows": rows, "gaps": gaps, "governance_principle": config.GOVERNANCE_PRINCIPLE,
                "counts": {"assets": len(assets), "threats": len(rows), "approved_threats": sum(1 for r in rows if r["status"]["threat"] == "approved")}}

    # ------------------------------------------------------------ full workflow
    def run_workflow(self, project_id, user="system") -> dict:
        t0 = time.perf_counter()
        assets = self.identify_assets(project_id, user)["assets"]
        surface = self.map_attack_surface(project_id, user=user)
        threats = []
        present = self.project_interfaces(project_id)
        for iface in [i for i in WORKFLOW_ORDER if i in present]:
            res = self.recommend_threats(project_id, f"Suggest threat scenarios for the {INTERFACES[iface]} interface of the telematics unit",
                                         interfaces=[iface], user=user)
            threats += res.get("threats", [])
        for t in db.get_items(project_id, "threat"):
            self.assess_risk(project_id, t["ref"], user)
            self.recommend_mitigations(project_id, t["ref"], user)
        secs = round(time.perf_counter() - t0, 2)
        db.audit(user, project_id, "run_workflow", detail={"seconds": secs})
        return {"seconds": secs, "assets": len(assets), "surface_entries": len(surface), "threats": len(db.get_items(project_id, "threat")),
                "engine": self.llm.engine}

    # ------------------------------------------------------------ cited Q&A
    def ask(self, project_id, question, user="system") -> dict:
        guard = check_scope(question)
        if not guard["allowed"]:
            db.audit(user, project_id, "request_declined", detail={"reason": guard["reason"]})
            return {"status": "declined", "answer": guard["message"], "citations": [], "mitigation_guidance": self._mitigation_guidance(question, project_id)}
        ifaces = detect_interfaces(question) or None
        hits = self.search(question, config.GLOBAL_SCOPE, None, ifaces, k=5) + (self.search(question, project_id, None, ifaces, k=3) if project_id else [])
        if not hits:
            return {"status": "insufficient_context", "answer": "The approved knowledge base has no supporting passage for this question.", "citations": []}
        cites = [{"citation": h.meta["citation"], "text": h.text, "score": h.score} for h in hits]
        answer = None
        if self.llm.available:
            res = self.llm.complete_json(SYSTEM_PROMPT, json.dumps({"task": "Answer the QUESTION from CONTEXT only. Cite passage ids in text as [id]. Return {\"answer\":\"...\"}.",
                                                                 "question": question, "context": [{"id": c["citation"], "text": c["text"]} for c in cites]}))
            if isinstance(res, dict) and isinstance(res.get("answer"), str):
                answer = res["answer"]
        if not answer:
            answer = "Most relevant approved passages:\n" + "\n".join(f"- {c['text']} [{c['citation']}]" for c in cites[:3])
        return {"status": "ok", "answer": answer, "citations": cites, "engine": self.llm.engine}
