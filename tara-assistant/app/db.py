"""SQLite persistence: projects, users, items, reviews, approvals, audit trail, run timings."""
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, display TEXT, role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '', created_at TEXT, created_by TEXT);
CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT, document TEXT, doc_type TEXT, scope TEXT,
  version TEXT, review_date TEXT, sha256 TEXT, n_chunks INTEGER, avg_tokens REAL, interfaces TEXT, ingested_at TEXT);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
  parent_ref TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', data TEXT NOT NULL, engine TEXT DEFAULT '',
  created_at TEXT, updated_at TEXT, UNIQUE(project_id, kind, ref));
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL, reviewer TEXT, decision TEXT, rationale TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, username TEXT, project_id TEXT, action TEXT, entity TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT, step TEXT, ms REAL, engine TEXT, ts TEXT);
"""

SEED_USERS = [
    ("engineer1", "Cybersecurity engineer", "engineer"),
    ("manager1", "Cybersecurity manager", "manager"),
    ("auditor1", "Compliance / audit", "auditor"),
]
# role -> allowed permissions (role-based access control)
PERMISSIONS = {
    "engineer": {"read", "run", "review", "ingest"},
    "manager": {"read", "run", "review", "ingest", "project"},
    "auditor": {"read"},
}
PENDING_STATUSES = ("pending",)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def conn():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.executescript(SCHEMA)
        for u in SEED_USERS:
            c.execute("INSERT OR IGNORE INTO users VALUES(?,?,?)", u)


def get_user(username: str):
    with conn() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None


def allowed(role: str, perm: str) -> bool:
    return perm in PERMISSIONS.get(role, set())


def audit(username, project_id, action, entity="", detail=None):
    with conn() as c:
        c.execute("INSERT INTO audit_log(ts,username,project_id,action,entity,detail) VALUES(?,?,?,?,?,?)",
                  (now(), username, project_id, action, entity, json.dumps(detail or {})))


def audit_trail(project_id, limit=500):
    with conn() as c:
        rows = c.execute("SELECT * FROM audit_log WHERE project_id=? ORDER BY id DESC LIMIT ?", (project_id, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["detail"] = json.loads(d["detail"] or "{}")
        out.append(d)
    return out


def record_run(project_id, step, ms, engine):
    with conn() as c:
        c.execute("INSERT INTO runs(project_id,step,ms,engine,ts) VALUES(?,?,?,?,?)", (project_id, step, ms, engine, now()))


def create_project(pid, name, description, user):
    with conn() as c:
        c.execute("INSERT INTO projects VALUES(?,?,?,?,?)", (pid, name, description, now(), user))


def list_projects():
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM projects ORDER BY created_at")]


def get_project(pid):
    with conn() as c:
        r = c.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
        return dict(r) if r else None


def add_document_log(project_id, rec):
    with conn() as c:
        c.execute("DELETE FROM documents WHERE project_id=? AND document=?", (project_id, rec["document"]))
        c.execute("INSERT INTO documents(project_id,document,doc_type,scope,version,review_date,sha256,n_chunks,avg_tokens,interfaces,ingested_at)"
                  " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (project_id, rec["document"], rec["doc_type"], rec["scope"], rec["version"], rec["review_date"], rec["sha256"],
                   rec["n_chunks"], rec["avg_tokens"], ",".join(rec["interfaces"]), now()))


def list_documents(project_id):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM documents WHERE project_id=? ORDER BY id", (project_id,))]


# ---- items
def _row(r):
    d = dict(r)
    d["data"] = json.loads(d["data"])
    return d


def upsert_item(project_id, kind, ref, data, parent_ref="", engine="", keep_status=True):
    with conn() as c:
        ex = c.execute("SELECT * FROM items WHERE project_id=? AND kind=? AND ref=?", (project_id, kind, ref)).fetchone()
        if ex:
            status = ex["status"] if keep_status else "pending"
            c.execute("UPDATE items SET data=?, engine=?, parent_ref=?, status=?, updated_at=? WHERE id=?",
                      (json.dumps(data), engine, parent_ref, status, now(), ex["id"]))
            return ex["id"]
        cur = c.execute("INSERT INTO items(project_id,kind,ref,parent_ref,status,data,engine,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (project_id, kind, ref, parent_ref, "pending", json.dumps(data), engine, now(), now()))
        return cur.lastrowid


def get_items(project_id, kind=None, parent_ref=None):
    q, a = "SELECT * FROM items WHERE project_id=?", [project_id]
    if kind:
        q += " AND kind=?"; a.append(kind)
    if parent_ref is not None:
        q += " AND parent_ref=?"; a.append(parent_ref)
    with conn() as c:
        return [_row(r) for r in c.execute(q + " ORDER BY id", a)]


def get_item(project_id, kind, ref):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE project_id=? AND kind=? AND ref=?", (project_id, kind, ref)).fetchone()
        return _row(r) if r else None


def get_item_by_id(project_id, item_id):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE project_id=? AND id=?", (project_id, item_id)).fetchone()
        return _row(r) if r else None


def next_ref(project_id, kind, prefix):
    with conn() as c:
        n = c.execute("SELECT COUNT(*) FROM items WHERE project_id=? AND kind=?", (project_id, kind)).fetchone()[0]
    return f"{prefix}{n + 1}"


def delete_items(project_id, kind=None):
    with conn() as c:
        if kind:
            c.execute("DELETE FROM items WHERE project_id=? AND kind=?", (project_id, kind))
        else:
            c.execute("DELETE FROM items WHERE project_id=?", (project_id,))


def add_review(item_id, reviewer, decision, rationale):
    status = {"approve": "approved", "reject": "rejected", "needs_change": "needs_change"}[decision]
    with conn() as c:
        c.execute("INSERT INTO reviews(item_id,reviewer,decision,rationale,ts) VALUES(?,?,?,?,?)", (item_id, reviewer, decision, rationale, now()))
        c.execute("UPDATE items SET status=?, updated_at=? WHERE id=?", (status, now(), item_id))
    return status


def get_reviews(item_id):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM reviews WHERE item_id=? ORDER BY id", (item_id,))]


def run_stats(project_id):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT step, ROUND(AVG(ms),1) avg_ms, COUNT(*) n FROM runs WHERE project_id=? GROUP BY step", (project_id,))]
