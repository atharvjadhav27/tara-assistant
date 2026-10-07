"""FastAPI service layer. Identity is taken from the X-User header (pilot); role-based access is enforced per endpoint.
For enterprise use put this behind SSO / an API gateway that sets the header."""
import re
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Response, UploadFile
from pydantic import BaseModel, Field

from . import config, db, reports
from .agent import AgentError, TaraAgent

_agent: TaraAgent | None = None


def agent() -> TaraAgent:
    global _agent
    if _agent is None:
        _agent = TaraAgent()
    return _agent


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    agent().ensure_global_knowledge()
    if not db.list_projects():  # pilot convenience: a sample project is always available
        db.create_project("TCU-Gen2", "TCU-Gen2 (sample)", "Sample telematics control unit used for the pilot (illustrative data).", "system")
    yield


app = FastAPI(title="Automotive Cybersecurity TARA Assistant", version="1.0.0", lifespan=lifespan,
              description="AI-assisted ISO/SAE 21434 TARA support. All output is advisory and requires engineer approval.")


def user_with(perm: str):
    def dep(x_user: str = Header(default="engineer1")):
        u = db.get_user(x_user)
        if not u:
            raise HTTPException(401, "Unknown user")
        if not db.allowed(u["role"], perm):
            raise HTTPException(403, f"Role '{u['role']}' may not perform this action")
        return u
    return dep


@app.exception_handler(AgentError)
async def agent_error(_, exc: AgentError):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": str(exc)}, status_code=exc.code)


def project_or_404(pid: str):
    p = db.get_project(pid)
    if not p:
        raise HTTPException(404, "Unknown project")
    return p


class ProjectIn(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{2,40}$")
    name: str
    description: str = ""


class ThreatQuery(BaseModel):
    query: str = Field(min_length=3, max_length=1000)
    interfaces: list[str] | None = None
    top_k: int | None = Field(default=None, ge=1, le=20)


class ReviewIn(BaseModel):
    decision: str = Field(pattern="^(approve|reject|needs_change)$")
    rationale: str = ""


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


# ------------------------------------------------------------------ system
@app.get("/health")
def health():
    a = agent()
    return {"status": "ok", "llm_engine": a.llm.engine, "embedder": a.embedder.name,
            "global_chunks": a.store.count(project=config.GLOBAL_SCOPE), "advisory_only": True}


@app.get("/users")
def users():
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM users")]


# ------------------------------------------------------------------ projects & documents
@app.get("/projects")
def projects(u=Depends(user_with("read"))):
    return db.list_projects()


@app.post("/projects", status_code=201)
def create_project(p: ProjectIn, u=Depends(user_with("project"))):
    if db.get_project(p.id):
        raise HTTPException(409, "Project already exists")
    db.create_project(p.id, p.name, p.description, u["username"])
    db.audit(u["username"], p.id, "create_project", p.id)
    return db.get_project(p.id)


@app.post("/projects/{pid}/documents")
async def upload_document(pid: str, file: UploadFile = File(...), doc_type: str | None = Form(default=None), u=Depends(user_with("ingest"))):
    project_or_404(pid)
    data = await file.read()
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "File too large (25 MB limit)")
    safe = re.sub(r"[^\w.\-]", "_", file.filename or "upload")
    try:
        return agent().ingest_bytes(pid, safe, data, doc_type, u["username"])
    except (ValueError, KeyError) as exc:
        raise HTTPException(422, f"Could not parse document: {exc}")


@app.post("/projects/{pid}/documents/sample")
def load_sample(pid: str, u=Depends(user_with("ingest"))):
    project_or_404(pid)
    return agent().load_sample_project(pid, u["username"])


@app.get("/projects/{pid}/documents")
def documents(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.list_documents(pid)


# ------------------------------------------------------------------ workflow steps
@app.post("/projects/{pid}/assets/identify")
def identify(pid: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().identify_assets(pid, u["username"])


@app.get("/projects/{pid}/assets")
def assets(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return {"assets": db.get_items(pid, "asset"), "boundaries": db.get_items(pid, "boundary")}


@app.post("/projects/{pid}/attack-surface/map")
def map_surface(pid: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().map_attack_surface(pid, user=u["username"])


@app.get("/projects/{pid}/attack-surface")
def surface(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "surface")


@app.post("/projects/{pid}/threats/recommend")
def recommend(pid: str, q: ThreatQuery, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().recommend_threats(pid, q.query, q.interfaces, q.top_k, u["username"])


@app.get("/projects/{pid}/threats")
def threats(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "threat")


@app.post("/projects/{pid}/threats/{ref}/assess")
def assess(pid: str, ref: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().assess_risk(pid, ref, u["username"])


@app.get("/projects/{pid}/ratings")
def ratings(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "rating")


@app.post("/projects/{pid}/threats/{ref}/mitigations")
def mitigations(pid: str, ref: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().recommend_mitigations(pid, ref, u["username"])


@app.get("/projects/{pid}/mitigations")
def list_mitigations(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_items(pid, "mitigation")


@app.post("/projects/{pid}/workflow/run")
def run_workflow(pid: str, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().run_workflow(pid, u["username"])


@app.post("/projects/{pid}/ask")
def ask(pid: str, q: AskIn, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().ask(pid, q.question, u["username"])


# ------------------------------------------------------------------ review / audit
@app.post("/projects/{pid}/items/{item_id}/review")
def review(pid: str, item_id: int, r: ReviewIn, u=Depends(user_with("review"))):
    project_or_404(pid)
    item = agent().review_item(pid, item_id, u["username"], r.decision, r.rationale)
    item["reviews"] = db.get_reviews(item_id)
    return item


@app.get("/projects/{pid}/items/{item_id}/reviews")
def item_reviews(pid: str, item_id: int, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.get_reviews(item_id)


@app.post("/projects/{pid}/items/{item_id}/regenerate")
def regenerate(pid: str, item_id: int, u=Depends(user_with("run"))):
    project_or_404(pid)
    return agent().regenerate(pid, item_id, u["username"])


@app.get("/projects/{pid}/audit")
def audit(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.audit_trail(pid)


@app.get("/projects/{pid}/metrics")
def metrics(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    return db.run_stats(pid)


# ------------------------------------------------------------------ traceability
@app.get("/projects/{pid}/traceability")
def traceability(pid: str, include_rejected: bool = False, u=Depends(user_with("read"))):
    project_or_404(pid)
    return agent().traceability(pid, include_rejected)


@app.get("/projects/{pid}/traceability.csv")
def trace_csv(pid: str, u=Depends(user_with("read"))):
    project_or_404(pid)
    db.audit(u["username"], pid, "export_csv")
    return Response(reports.to_csv(agent().traceability(pid)), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="traceability_{pid}.csv"'})


@app.get("/projects/{pid}/traceability.pdf")
def trace_pdf(pid: str, u=Depends(user_with("read"))):
    p = project_or_404(pid)
    db.audit(u["username"], pid, "export_pdf")
    return Response(reports.to_pdf(agent().traceability(pid), p["name"]), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="traceability_{pid}.pdf"'})
