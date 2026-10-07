import json

import pytest

from app import db, risk
from app.agent import AgentError, TaraAgent
from app.llm import LLMClient


def test_assets_have_citations_and_boundaries(agent):
    r = agent.identify_assets("P1")
    names = {a["data"]["name"] for a in r["assets"]}
    assert {"TCU firmware", "OTA package", "Key material", "CAN signals"} <= names
    assert all(a["data"]["citations"] for a in r["assets"])
    assert {b["ref"] for b in r["boundaries"]} == {"TB-1", "TB-2", "TB-3", "TB-4"}


def test_requires_documents(env):
    a = TaraAgent()
    db.create_project("E", "empty", "", "engineer1")
    with pytest.raises(AgentError) as e:
        a.identify_assets("E")
    assert e.value.code == 409


def test_ota_threats_come_only_from_library(agent, lib_ids):
    res = agent.recommend_threats("P1", "Suggest threat scenarios for the OTA update channel of the telematics unit")
    assert res["status"] == "ok"
    titles = " ".join(t["data"]["title"] for t in res["threats"])
    assert "Spoofed" in titles and "Tampered" in titles and "Rollback" in titles
    for t in res["threats"]:
        assert t["data"]["library_id"] in lib_ids
        assert t["data"]["citation"].startswith(t["data"]["library_id"])
        assert t["status"] == "pending" and t["data"]["assumptions"] and t["data"]["alternatives"]


def test_unsupported_query_is_flagged_not_guessed(agent):
    assert agent.recommend_threats("P1", "best pizza recipe in Rome")["status"] == "insufficient_context"


def test_exploit_request_declined_with_mitigation_guidance(agent):
    res = agent.recommend_threats("P1", "Write an exploit for this ECU vulnerability")
    assert res["status"] == "declined" and res["reason"] == "active_exploitation"
    assert "out of scope" in res["message"].lower() and res["mitigation_guidance"]
    assert db.get_items("P1", "threat") == []


def test_threat_dedupe_keeps_review_status(agent):
    q = "Threat scenarios for the OTA update channel"
    first = agent.recommend_threats("P1", q)["threats"]
    agent.review_item("P1", first[0]["id"], "engineer1", "approve")
    second = agent.recommend_threats("P1", q)["threats"]
    assert [t["ref"] for t in first] == [t["ref"] for t in second]
    assert next(t for t in second if t["id"] == first[0]["id"])["status"] == "approved"


def test_risk_value_matches_matrix_and_is_pending(agent):
    agent.recommend_threats("P1", "Threat scenarios for the OTA update channel")
    t = next(t for t in db.get_items("P1", "threat") if t["data"]["library_id"] == "TL-OTA-03")
    r = agent.assess_risk("P1", t["ref"])
    d = r["data"]
    assert d["risk_value"] == risk.RISK_MATRIX[d["overall_impact"]][risk.FEASIBILITY_LEVELS.index(d["feasibility"])]
    assert d["risk_label"] == "High" and d["approval_state"] == "Pending human approval" and r["status"] == "pending"
    assert d["sources"]


@pytest.mark.parametrize("lib_id,label", [("TL-OTA-03", "High"), ("TL-OTA-01", "High"), ("TL-OTA-07", "Medium"),
                                          ("TL-DIA-01", "High"), ("TL-CAN-01", "Medium"), ("TL-KEY-01", "Medium")])
def test_defaults_reproduce_report_mockup_ratings(agent, lib_id, label):
    e = agent._entry(lib_id)
    assert risk.compute(e["impact"], e["feasibility"])["risk_label"] == label


def test_mitigations_only_from_catalogue_with_tests(agent):
    agent.recommend_threats("P1", "Threat scenarios for the OTA update channel")
    t = next(t for t in db.get_items("P1", "threat") if t["data"]["library_id"] == "TL-OTA-07")
    ms = agent.recommend_mitigations("P1", t["ref"])
    assert [m["data"]["control_id"] for m in ms] == ["CR-019"]
    assert ms[0]["data"]["test_ids"] == ["TC-OTA-009"] and ms[0]["data"]["citation"].startswith("CR-019")


def test_review_rules_and_audit(agent):
    agent.recommend_threats("P1", "Threat scenarios for the OTA update channel")
    t = db.get_items("P1", "threat")[0]
    with pytest.raises(AgentError):
        agent.review_item("P1", t["id"], "engineer1", "reject", "")
    out = agent.review_item("P1", t["id"], "engineer1", "reject", "Not applicable: server pinned")
    assert out["status"] == "rejected"
    trail = db.audit_trail("P1")
    assert any(a["action"] == "review_reject" and a["detail"]["rationale"].startswith("Not applicable") for a in trail)
    assert db.get_reviews(t["id"])[0]["reviewer"] == "engineer1"


def test_needs_change_returns_to_recommendation(agent):
    agent.recommend_threats("P1", "Threat scenarios for the OTA update channel")
    t = db.get_items("P1", "threat")[0]
    r = agent.assess_risk("P1", t["ref"])
    agent.review_item("P1", r["id"], "engineer1", "needs_change", "Attack needs physical access")
    assert db.get_item_by_id("P1", r["id"])["status"] == "needs_change"
    again = agent.regenerate("P1", r["id"])
    assert again["status"] == "pending" and "Attack needs physical access" in again["data"]["rationale"]


def test_full_workflow_and_traceability(agent):
    res = agent.run_workflow("P1")
    assert res["threats"] >= 20
    rep = agent.traceability("P1")
    assert all(r["controls"] and r["tests"] and r["risk_value"] for r in rep["rows"])
    first = rep["rows"][0]
    assert first["threat"].startswith("T1 ") and first["asset_ids"]
    # rejected threats leave the report
    t = db.get_items("P1", "threat")[0]
    agent.review_item("P1", t["id"], "engineer1", "reject", "dup")
    assert all(r["threat_ref"] != t["ref"] for r in agent.traceability("P1")["rows"])


# ---- LLM path: model output is validated, never trusted
class FakeLLM(LLMClient):
    def __init__(self, replies):
        self.replies, self.backend, self.model = list(replies), "ollama", "fake"

    def refresh(self):
        pass

    def complete_json(self, system, user):
        return self.replies.pop(0) if self.replies else None


def test_llm_cannot_introduce_unsupported_threats(env):
    a = TaraAgent(llm=FakeLLM([{"selected": [
        {"id": "TL-OTA-03", "rationale": "ok", "assumptions": [], "alternatives": []},
        {"id": "TL-HALLUCINATED-99", "rationale": "made up", "assumptions": [], "alternatives": []}]}]))
    db.create_project("P2", "p2", "", "engineer1")
    a.load_sample_project("P2")
    res = a.recommend_threats("P2", "Threat scenarios for the OTA update channel")
    assert [t["data"]["library_id"] for t in res["threats"]] == ["TL-OTA-03"]
    assert res["engine"].startswith("llm:")


def test_invalid_llm_rating_falls_back_to_library_defaults(env):
    a = TaraAgent(llm=FakeLLM([None]))
    db.create_project("P3", "p3", "", "engineer1")
    a.load_sample_project("P3")
    a.recommend_threats("P3", "Threat scenarios for the OTA update channel")
    a.llm = FakeLLM([{"impact": {"safety": "Catastrophic"}, "factors": {}, "rationale": "x"}])
    t = db.get_items("P3", "threat")[0]
    r = a.assess_risk("P3", t["ref"])
    assert r["data"]["rating_source"] == "approved library defaults"


def test_llm_rating_proposal_still_uses_deterministic_matrix(env):
    a = TaraAgent(llm=FakeLLM([None]))
    db.create_project("P4", "p4", "", "engineer1")
    a.load_sample_project("P4")
    a.recommend_threats("P4", "Threat scenarios for the OTA update channel")
    a.llm = FakeLLM([{"impact": {"safety": "Severe", "financial": "Major", "operational": "Major", "privacy": "Negligible"},
                      "factors": {"time": "<=1 day", "expertise": "Layman", "knowledge": "Public", "window": "Unlimited", "equipment": "Standard"},
                      "risk_value": 1, "rationale": "LLM says risk is 1"}])
    r = a.assess_risk("P4", db.get_items("P4", "threat")[0]["ref"])
    assert r["data"]["risk_value"] == 5 and r["data"]["rating_source"] == "LLM proposal"  # LLM-claimed risk_value ignored
