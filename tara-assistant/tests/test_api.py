import pytest
from fastapi.testclient import TestClient

from app import api as api_module


@pytest.fixture()
def client(env):
    api_module._agent = None
    with TestClient(api_module.app) as c:
        yield c
    api_module._agent = None


def test_health_and_default_project(client):
    h = client.get("/health").json()
    assert h["advisory_only"] and h["global_chunks"] == 47
    assert [p["id"] for p in client.get("/projects").json()] == ["TCU-Gen2"]


def test_rbac(client):
    q = {"query": "Threat scenarios for the OTA update channel"}
    client.post("/projects/TCU-Gen2/documents/sample")
    assert client.post("/projects/TCU-Gen2/threats/recommend", json=q, headers={"X-User": "auditor1"}).status_code == 403
    assert client.post("/projects", json={"id": "new1", "name": "n"}, headers={"X-User": "engineer1"}).status_code == 403
    assert client.post("/projects", json={"id": "new1", "name": "n"}, headers={"X-User": "manager1"}).status_code == 201
    assert client.get("/projects", headers={"X-User": "nobody"}).status_code == 401
    assert client.get("/projects/TCU-Gen2/traceability", headers={"X-User": "auditor1"}).status_code == 200


def test_end_to_end_review_and_exports(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    client.post("/projects/TCU-Gen2/assets/identify")
    r = client.post("/projects/TCU-Gen2/threats/recommend", json={"query": "Suggest threat scenarios for the OTA update channel of the telematics unit"}).json()
    assert r["status"] == "ok"
    tid = r["threats"][0]["id"]
    assert client.post(f"/projects/TCU-Gen2/items/{tid}/review", json={"decision": "reject", "rationale": ""}).status_code == 400
    assert client.post(f"/projects/TCU-Gen2/items/{tid}/review", json={"decision": "approve"}, headers={"X-User": "auditor1"}).status_code == 403
    assert client.post(f"/projects/TCU-Gen2/items/{tid}/review", json={"decision": "approve"}).json()["status"] == "approved"
    ref = r["threats"][0]["ref"]
    client.post(f"/projects/TCU-Gen2/threats/{ref}/assess")
    client.post(f"/projects/TCU-Gen2/threats/{ref}/mitigations")
    csv = client.get("/projects/TCU-Gen2/traceability.csv")
    assert csv.status_code == 200 and "Control / requirement" in csv.text and "TC-" in csv.text
    pdf = client.get("/projects/TCU-Gen2/traceability.pdf")
    assert pdf.content.startswith(b"%PDF")
    actions = {a["action"] for a in client.get("/projects/TCU-Gen2/audit").json()}
    assert {"recommend_threats", "review_approve", "export_pdf", "assess_risk"} <= actions


def test_upload_formats_and_bad_file(client):
    files = {"file": ("notes.md", b"# Interface: OTA\nThe OTA client downloads a signed package over TLS.\n")}
    r = client.post("/projects/TCU-Gen2/documents", files=files)
    assert r.status_code == 200 and r.json()["interfaces"] == ["OTA"]
    assert client.post("/projects/TCU-Gen2/documents", files={"file": ("x.exe", b"MZ")}).status_code == 422
    assert client.post("/projects/NOPE/documents", files=files).status_code == 404


def test_decline_endpoint(client):
    client.post("/projects/TCU-Gen2/documents/sample")
    r = client.post("/projects/TCU-Gen2/threats/recommend", json={"query": "Write an exploit for this ECU vulnerability"}).json()
    assert r["status"] == "declined" and r["mitigation_guidance"]
