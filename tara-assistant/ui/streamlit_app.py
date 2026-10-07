"""Streamlit pilot UI for the Automotive Cybersecurity TARA Assistant (talks to the FastAPI service layer)."""
import html
import os

import httpx
import pandas as pd
import streamlit as st

API = os.getenv("TARA_API_URL", "http://localhost:8000")
NAVY = "#1F3864"
PAGES = ["Architecture input", "Assets", "Attack surface", "Threat scenarios", "Risk assessment", "Mitigations", "Traceability report", "Audit trail"]
ROLES = {"engineer1": "Cybersecurity engineer", "manager1": "Cybersecurity manager", "auditor1": "Compliance / audit"}
RISK_BG = {"Critical": "#F4B6B6", "High": "#F9CBAA", "Medium": "#FFE699", "Low": "#D5E8D4", "Very low": "#E2F0D9"}
STATUS_BG = {"pending": "#EEEEEE", "approved": "#C5E0B4", "rejected": "#F4B6B6", "needs_change": "#FFE699"}
STATUS_TXT = {"pending": "Pending review", "approved": "Approved", "rejected": "Rejected", "needs_change": "Needs change"}
STATUS_LINE = "Status: Pending engineer review  |  AI suggestions only; assumptions and alternatives available per item"

st.set_page_config(page_title="TARA Assistant", page_icon="🛡️", layout="wide")
st.markdown(f"""
<style>
h1, h2, h3 {{ color: {NAVY} !important; }}
section[data-testid="stSidebar"] {{ background: #F0F2F6; }}
.chip {{ display:inline-block; padding:3px 10px; border-radius:6px; font-size:0.82rem; margin:2px 6px 2px 0; border:1px solid transparent; }}
.chip.src {{ background:#EAF0FB; border-color:#9DB4E0; color:{NAVY}; }}
.gov {{ background:#FFF2CC; border:1px solid #D6B656; border-radius:8px; padding:12px 16px; margin:12px 0; }}
.gov b {{ color:#7F6000; }}
.statusline {{ color:#7F6000; font-size:0.9rem; margin-top:18px; }}
.small {{ color:#555; font-size:0.85rem; }}
.stButton > button[kind="primary"] {{ background:{NAVY}; border-color:{NAVY}; }}
</style>""", unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def esc(x) -> str:
    return html.escape(str(x))


def chip(text, bg=None, cls=""):
    style = f' style="background:{bg}"' if bg else ""
    return f'<span class="chip {cls}"{style}>{esc(text)}</span>'


def call(method, path, **kw):
    headers = {"X-User": st.session_state.get("user", "engineer1")}
    try:
        r = httpx.request(method, API + path, headers=headers, timeout=180, **kw)
    except httpx.HTTPError:
        st.error(f"Cannot reach the TARA service at {API}. Start it with `uvicorn app.api:app` (see README).")
        st.stop()
    if r.status_code >= 400:
        try:
            msg = r.json().get("detail", r.text)
        except Exception:
            msg = r.text
        st.error(f"{msg}")
        return None
    return r


def get_json(path, **kw):
    r = call("GET", path, **kw)
    return r.json() if r is not None else None


def post_json(path, body=None):
    r = call("POST", path, json=body)
    return r.json() if r is not None else None


def can(perm: str) -> bool:
    role = st.session_state.get("user", "engineer1")
    return role != "auditor1" or perm == "read"


def status_line():
    st.markdown(f'<div class="statusline">{esc(STATUS_LINE)}</div>', unsafe_allow_html=True)


def review_controls(pid, item, key):
    """Approve / Reject / Needs change with stored rationale (audit trail)."""
    st.markdown(chip(STATUS_TXT[item["status"]], STATUS_BG[item["status"]]), unsafe_allow_html=True)
    if not can("review"):
        st.caption("Read-only role")
        return
    rat = st.text_input("Rationale (required to reject or request change)", key=f"rat-{key}", label_visibility="collapsed",
                        placeholder="Rationale (required to reject / request change)")
    c1, c2, c3 = st.columns(3)
    for col, (label, dec) in zip((c1, c2, c3), (("Approve", "approve"), ("Reject", "reject"), ("Needs change", "needs_change"))):
        if col.button(label, key=f"{key}-{dec}", width="stretch"):
            r = call("POST", f"/projects/{pid}/items/{item['id']}/review", json={"decision": dec, "rationale": rat})
            if r is not None:
                st.rerun()
    if item["status"] == "needs_change" and item["kind"] in ("rating", "mitigation"):
        if st.button("Regenerate recommendation", key=f"{key}-regen"):
            if call("POST", f"/projects/{pid}/items/{item['id']}/regenerate") is not None:
                st.rerun()


# ------------------------------------------------------------------ sidebar
users = ROLES
with st.sidebar:
    st.markdown("## TARA Assistant")
    projects = get_json("/projects") or []
    if not projects:
        st.warning("No projects yet.")
        st.stop()
    names = {p["id"]: p["name"] for p in projects}
    pid = st.selectbox("Project", list(names), format_func=lambda i: names[i])
    st.caption(f"Project: {names[pid]}")
    page = st.radio("Navigation", PAGES, label_visibility="collapsed", key="page")
    st.divider()
    st.selectbox("Role", list(users), format_func=lambda u: users[u], key="user")
    health = get_json("/health") or {}
    st.caption(f"Engine: {health.get('llm_engine', '?')}  \nEmbeddings: {health.get('embedder', '?')}")


# ------------------------------------------------------------------ pages
def page_input():
    st.title("Architecture input")
    st.write("Ingest architecture descriptions, communication matrices, asset catalogues and (optionally) approved project knowledge. "
             "Documents are cleaned, chunked, embedded and stored in the local vector store with metadata.")
    c1, c2 = st.columns([1, 2])
    with c1:
        if can("ingest") and st.button("Load sample TCU-Gen2 documents", type="primary"):
            if post_json(f"/projects/{pid}/documents/sample") is not None:
                st.rerun()
        if can("run") and st.button("Run full TARA workflow"):
            with st.spinner("Running assets, attack surface, threats, risk and mitigations..."):
                res = post_json(f"/projects/{pid}/workflow/run")
            if res:
                st.success(f"Workflow finished in {res['seconds']} s ({res['assets']} assets, {res['surface_entries']} attack-surface entries, "
                           f"{res['threats']} threat scenarios). All items are pending engineer review.")
    with c2:
        files = st.file_uploader("Upload documents (PDF, DOCX, XLSX, CSV, JSON, MD, TXT)", accept_multiple_files=True,
                                 type=["pdf", "docx", "xlsx", "csv", "json", "md", "txt"], disabled=not can("ingest"))
        if files and st.button("Ingest uploaded files"):
            for f in files:
                r = call("POST", f"/projects/{pid}/documents", files={"file": (f.name, f.getvalue())})
                if r is not None:
                    j = r.json()
                    st.success(f"{j['document']}: {j['n_chunks']} chunks ({j['doc_type']})")
    st.subheader("Ingestion log")
    docs = get_json(f"/projects/{pid}/documents") or []
    if docs:
        st.dataframe(pd.DataFrame(docs)[["document", "doc_type", "scope", "n_chunks", "avg_tokens", "interfaces", "review_date", "sha256", "ingested_at"]],
                     hide_index=True, width="stretch")
    else:
        st.info("No project documents yet. Load the sample documents or upload your own.")
    status_line()


def page_assets():
    st.title("Assets and trust boundaries")
    if can("run") and st.button("Identify assets", type="primary"):
        if post_json(f"/projects/{pid}/assets/identify") is not None:
            st.rerun()
    data = get_json(f"/projects/{pid}/assets") or {"assets": [], "boundaries": []}
    if not data["assets"]:
        st.info("No assets yet. Ingest documents, then identify assets.")
    for a in data["assets"]:
        d = a["data"]
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            with c1:
                st.markdown(f"**{esc(d['asset_id'])}  {esc(d['name'])}**")
                st.write(d["description"])
                st.markdown(chip(f"{d['type']} | {d['interface']}") + chip(f"Origin: {d['origin']}") +
                            "".join(chip("Source: " + c, cls="src") for c in d["citations"][:3]), unsafe_allow_html=True)
            with c2:
                review_controls(pid, a, f"asset-{a['id']}")
    if data["boundaries"]:
        st.subheader("Trust boundaries")
        for b in data["boundaries"]:
            st.markdown(f"**{esc(b['data']['boundary_id'])}**  {esc(b['data']['description'])}  " + chip("Source: " + b["data"]["citations"][0], cls="src"),
                        unsafe_allow_html=True)
    status_line()


def page_surface():
    st.title("Attack surface")
    if can("run") and st.button("Map attack surface", type="primary"):
        if post_json(f"/projects/{pid}/attack-surface/map") is not None:
            st.rerun()
    items = get_json(f"/projects/{pid}/attack-surface") or []
    if not items:
        st.info("No attack-surface map yet.")
    else:
        rows = [{"Interface": i["data"]["interface_name"], "Entry point": i["data"]["entry_point"], "Attack vector": i["data"]["vector"],
                 "Exposure": i["data"]["exposure"], "Linked assets": ", ".join(i["data"]["asset_names"]),
                 "Trust boundary": i["data"]["trust_boundary"], "Sources": " || ".join(i["data"]["citations"])} for i in items]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    status_line()


def threat_card(t):
    d = t["data"]
    with st.container(border=True):
        st.markdown(f"### {esc(t['ref'])}  {esc(d['title'])}")
        st.write(d["description"])
        st.markdown(chip("Source: " + d["citation"], cls="src") + chip("Proposed: " + d["proposed_risk"], RISK_BG.get(d["proposed_risk"], "#EEE")) +
                    chip(f"Asset: {', '.join(d['asset_names']) or 'none identified'}") + chip(f"STRIDE: {d['stride']}"), unsafe_allow_html=True)
        if d.get("warning"):
            st.warning(d["warning"])
        with st.expander("Rationale, assumptions and alternatives"):
            st.write(d["rationale"])
            st.markdown("**Assumptions**\n" + "\n".join(f"- {a}" for a in d["assumptions"]))
            st.markdown("**Alternatives**\n" + "\n".join(f"- {a}" for a in d["alternatives"]))
            st.caption(f"Retrieval score {d['retrieval_score']} | engine: {t['engine']}")
        review_controls(pid, t, f"threat-{t['id']}")


def page_threats():
    st.title("Threat scenario recommendation")
    q = st.text_input("Question", value="Suggest threat scenarios for the OTA update channel of the telematics unit", label_visibility="collapsed")
    with st.expander("Retrieval options"):
        top_k = st.slider("Top-k entries", 1, 15, 8)
    if can("run") and st.button("Retrieve", type="primary"):
        res = post_json(f"/projects/{pid}/threats/recommend", {"query": q, "top_k": top_k})
        st.session_state["last_threats"] = None
        if res:
            if res["status"] == "declined":
                st.error(res["message"])
                for m in res.get("mitigation_guidance", []):
                    st.markdown(f"- **{esc(m['control_id'])} {esc(m['title'])}**: {esc(m['requirement'])}  \n  <span class='small'>Source: {esc(m['citation'])}</span>",
                                unsafe_allow_html=True)
            elif res["status"] == "insufficient_context":
                st.warning(res["message"])
            else:
                st.session_state["last_threats"] = [t["id"] for t in res["threats"]]
                st.caption(f"Engine: {res['engine']}")
    all_t = get_json(f"/projects/{pid}/threats") or []
    last = st.session_state.get("last_threats")
    show_all = st.toggle("Show all stored threat scenarios", value=last is None)
    shown = all_t if show_all or not last else [t for t in all_t if t["id"] in last]
    if not shown:
        st.info("No threat scenarios yet. Ask a question above.")
    for t in shown:
        threat_card(t)
    with st.expander("Ask a cited question about the approved knowledge"):
        question = st.text_input("Question about threats or controls", key="askq")
        if st.button("Ask") and question:
            res = post_json(f"/projects/{pid}/ask", {"question": question})
            if res:
                (st.error if res["status"] == "declined" else st.write)(res["answer"])
                for c in res.get("citations", [])[:5]:
                    st.caption("Source: " + c["citation"])
    status_line()


def page_risk():
    st.title("Risk assessment")
    threats = [t for t in (get_json(f"/projects/{pid}/threats") or []) if t["status"] != "rejected"]
    ratings = {r["parent_ref"]: r for r in (get_json(f"/projects/{pid}/ratings") or [])}
    if not threats:
        st.info("No threat scenarios to assess yet.")
    if threats and can("run") and st.button("Assess all unassessed threats", type="primary"):
        for t in threats:
            if t["ref"] not in ratings:
                post_json(f"/projects/{pid}/threats/{t['ref']}/assess")
        st.rerun()
    for t in threats:
        r = ratings.get(t["ref"])
        with st.container(border=True):
            st.markdown(f"### {esc(t['ref'])}  {esc(t['data']['title'])}")
            if not r:
                if can("run") and st.button("Propose rating", key=f"assess-{t['id']}"):
                    post_json(f"/projects/{pid}/threats/{t['ref']}/assess")
                    st.rerun()
                continue
            d = r["data"]
            st.markdown(chip(f"Impact: {d['overall_impact']}") + chip(f"Attack feasibility: {d['feasibility']} (potential {d['attack_potential']})") +
                        chip(f"Risk: {d['risk_label']} ({d['risk_value']}/5)", RISK_BG.get(d["risk_label"], "#EEE")) + chip(d["approval_state"], "#FFF2CC"),
                        unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            c1.markdown("**Impact (S / F / O / P)**")
            c1.dataframe(pd.DataFrame([d["impact"]]), hide_index=True, width="stretch")
            c2.markdown("**Attack-potential factors**")
            c2.dataframe(pd.DataFrame([d["factors"]]), hide_index=True, width="stretch")
            st.write(d["rationale"])
            st.caption(f"Rating source: {d['rating_source']} | risk value computed by the deterministic matrix | engine: {r['engine']}")
            st.markdown("".join(chip("Source: " + s, cls="src") for s in d["sources"]), unsafe_allow_html=True)
            review_controls(pid, r, f"rating-{r['id']}")
    status_line()


def page_mitigations():
    st.title("Mitigations and requirement drafts")
    threats = [t for t in (get_json(f"/projects/{pid}/threats") or []) if t["status"] != "rejected"]
    mits = get_json(f"/projects/{pid}/mitigations") or []
    if threats and can("run") and st.button("Recommend mitigations for all threats", type="primary"):
        for t in threats:
            if not any(m["parent_ref"] == t["ref"] for m in mits):
                post_json(f"/projects/{pid}/threats/{t['ref']}/mitigations")
        st.rerun()
    if not mits:
        st.info("No mitigations yet.")
    for t in threats:
        ms = [m for m in mits if m["parent_ref"] == t["ref"]]
        if not ms:
            continue
        st.subheader(f"{t['ref']}  {t['data']['title']}")
        for m in ms:
            d = m["data"]
            with st.container(border=True):
                st.markdown(f"**{esc(d['requirement_id'])}  {esc(d['title'])} ({esc(d['control_id'])})**")
                st.write(d["requirement"])
                st.markdown(chip("Goal: " + d["cybersecurity_goal"]) + chip("Tests: " + ", ".join(d["test_ids"])) + chip("Source: " + d["citation"], cls="src"),
                            unsafe_allow_html=True)
                if d["alternatives"]:
                    with st.expander("Alternatives from the control catalogue"):
                        for a in d["alternatives"]:
                            st.markdown(f"- {a['control_id']} {a['title']}  ({a['citation']})")
                review_controls(pid, m, f"mit-{m['id']}")
    status_line()


def page_trace():
    st.title("Cybersecurity traceability report")
    rep = get_json(f"/projects/{pid}/traceability")
    if not rep or not rep["rows"]:
        st.info("Nothing to report yet. Run the workflow or approve threat scenarios first.")
        return
    rows = [{"Asset": r["asset"], "Threat scenario": r["threat"], "Risk": r["risk"], "Control / requirement": "; ".join(r["controls"]),
             "Test link": ", ".join(r["tests"]), "Review status": f"{r['status']['threat']} / {r['status']['rating']}"} for r in rep["rows"]]
    df = pd.DataFrame(rows)
    def colour(v):
        return f"background-color: {RISK_BG.get(str(v).replace(' (preliminary)', ''), '#FFFFFF')}"
    st.dataframe(df.style.map(colour, subset=["Risk"]), hide_index=True, width="stretch")
    st.markdown(f'<div class="gov"><b>Governance principle</b><br>{esc(rep["governance_principle"])}</div>', unsafe_allow_html=True)
    if rep["gaps"]:
        with st.expander(f"Coverage gaps ({len(rep['gaps'])})"):
            for g in rep["gaps"]:
                st.write("- " + g)
    c1, c2, _ = st.columns([1, 1, 4])
    pdf = call("GET", f"/projects/{pid}/traceability.pdf")
    csv = call("GET", f"/projects/{pid}/traceability.csv")
    if pdf is not None:
        c1.download_button("Export PDF", pdf.content, file_name=f"traceability_{pid}.pdf", mime="application/pdf", type="primary")
    if csv is not None:
        c2.download_button("Export CSV", csv.content, file_name=f"traceability_{pid}.csv", mime="text/csv", type="primary")
    st.caption("Sample data for illustration" if "sample" in names[pid].lower() else "")


def page_audit():
    st.title("Audit trail")
    rows = get_json(f"/projects/{pid}/audit") or []
    if rows:
        st.dataframe(pd.DataFrame([{**r, "detail": str(r["detail"])} for r in rows])[["ts", "username", "action", "entity", "detail"]],
                     hide_index=True, width="stretch")
    else:
        st.info("No audit entries yet.")
    stats = get_json(f"/projects/{pid}/metrics") or []
    if stats:
        st.subheader("Step latency (ms, average)")
        st.dataframe(pd.DataFrame(stats), hide_index=True)


{"Architecture input": page_input, "Assets": page_assets, "Attack surface": page_surface, "Threat scenarios": page_threats,
 "Risk assessment": page_risk, "Mitigations": page_mitigations, "Traceability report": page_trace, "Audit trail": page_audit}[page]()
