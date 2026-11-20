"""One local SQLite ledger shared by CLI, worker, API and Git hook."""

import json
import os
import shutil
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .provider import redact
from .snapshot import TOKEN
from .workspace import LAB, DEFAULT_HOME, CHECKOUT, EDITABLE, digest, json_bytes


from contextvars import ContextVar

LEDGER = ContextVar("ledger", default=None)


def home():
    if LEDGER.get():
        return LEDGER.get()
    legacy = CHECKOUT / ".laundromat-history"
    default = legacy if EDITABLE and (legacy / "history.sqlite").is_file() else DEFAULT_HOME
    path = Path(os.getenv("LAUNDROMAT_HOME", default)).expanduser().resolve()
    if (
        path == LAB
        or LAB in path.parents
        or any((p / ".phase1-workspace").is_file() for p in (path, *path.parents))
    ):
        raise ValueError("LAUNDROMAT_HOME must be outside the disposable Phase 1 workspace")
    return path


def encoded(value):
    return redact(json.dumps(value, sort_keys=True))


@contextmanager
def database():
    folder = home()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(folder / "history.sqlite", timeout=30)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS repositories(path TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, repo TEXT, key TEXT UNIQUE, fingerprint TEXT,
            created REAL, status TEXT, request TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS jobs(scan TEXT PRIMARY KEY, state TEXT, attempts INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS findings(scan TEXT, ordinal INTEGER, data TEXT, PRIMARY KEY(scan,ordinal));
        CREATE TABLE IF NOT EXISTS repairs(scan TEXT PRIMARY KEY, data TEXT);
        CREATE TABLE IF NOT EXISTS finding_repairs(scan TEXT,finding TEXT,data TEXT,PRIMARY KEY(scan,finding));
        CREATE TABLE IF NOT EXISTS previews(scan TEXT,finding TEXT,data TEXT,PRIMARY KEY(scan,finding));
        CREATE TABLE IF NOT EXISTS transitions(id INTEGER PRIMARY KEY AUTOINCREMENT, scan TEXT, finding TEXT,
              state TEXT, reason TEXT, actor TEXT, time REAL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, scan TEXT, kind TEXT, time REAL);
        CREATE TABLE IF NOT EXISTS push_evidence(scan TEXT,finding TEXT,data TEXT,PRIMARY KEY(scan,finding));
        CREATE TABLE IF NOT EXISTS acknowledgements(repo TEXT,snapshot TEXT,finding TEXT,PRIMARY KEY(repo,snapshot,finding));
        """)
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    finally:
        db.close()


def event(db, sid, kind):
    db.execute(
        "INSERT INTO events(scan,kind,time) VALUES(?,?,?)",
        (sid, TOKEN.sub("[redacted]", kind), time.time()),
    )


class Conflict(ValueError):
    pass


def submit(request, key=None, *, state="queued"):
    if TOKEN.search(request["snapshot"]["repository"]):
        raise ValueError("Repository path contains sensitive text")
    fingerprint = digest(json_bytes(request))
    logical_key = digest(key.encode()) if key else fingerprint
    with database() as db:
        prev = db.execute("SELECT id,fingerprint FROM scans WHERE key=?", (logical_key,)).fetchone()
        if prev:
            if prev["fingerprint"] != fingerprint:
                raise Conflict("Idempotency key already refers to different content")
            return prev["id"]
        sid = uuid.uuid4().hex
        repo = request["snapshot"]["repository"]
        db.execute("INSERT OR IGNORE INTO repositories VALUES(?)", (repo,))
        db.execute(
            "INSERT INTO scans VALUES(?,?,?,?,?,?,?,NULL)",
            (sid, repo, logical_key, fingerprint, time.time(), state, encoded(request)),
        )
        db.execute("INSERT INTO jobs(scan,state) VALUES(?,?)", (sid, state))
        event(db, sid, state)
    return sid


def finish(sid, result, *, refresh_demo=False):
    with database() as db:
        if db.execute("SELECT state FROM jobs WHERE scan=?", (sid,)).fetchone()[0] == "done":
            if not refresh_demo:
                return
            provenance = db.execute(
                "SELECT json_extract(request,'$.provenance') FROM scans WHERE id=?", (sid,)
            ).fetchone()[0]
            if provenance != "demo replay":
                raise ValueError("Only demo replay receipts can be reseeded")
            for table in ("repairs", "finding_repairs", "findings", "transitions"):
                db.execute(f"DELETE FROM {table} WHERE scan=?", (sid,))
        body = dict(result)
        for i, finding in enumerate(body.pop("findings", [])):
            if not result.get("workflow_version"):
                observe_once(db, sid, finding["id"], "candidate", finding["explanation"])
                state = finding.get("state", "candidate")
                if state != "candidate":
                    observe_once(
                        db,
                        sid,
                        finding["id"],
                        state,
                        finding.get("property", finding["explanation"]),
                    )
                elif (
                    "unsupported" in finding.get("repair_status", "")
                    or result["status"] == "incomplete"
                ):
                    transition(
                        db,
                        sid,
                        finding["id"],
                        "unsupported/incomplete",
                        finding["repair_status"],
                    )
            db.execute("INSERT INTO findings VALUES(?,?,?)", (sid, i, encoded(finding)))
        for t in body.get("replayed_transitions", []):
            db.execute(
                "INSERT INTO transitions(scan,finding,state,reason,actor,time) VALUES(?,?,?,?,?,?)",
                (sid, t["finding"], t["state"], t["reason"], t["actor"], t["time"]),
            )
        for o in body.get("structural_observations", []):
            if o["status"] != "review":
                transition(
                    db,
                    sid,
                    o["package"],
                    "checked-negative"
                    if o["status"] == "checked-negative"
                    else "unsupported/incomplete",
                    o.get("reason", "No install lifecycle declaration"),
                )
        if not result.get("findings") and result["status"] == "clean":
            transition(
                db,
                sid,
                None,
                "checked-negative",
                "Selected checks produced no candidates",
            )
        db.execute("DELETE FROM previews WHERE scan=?", (sid,))
        repair = body.pop("repair", None)
        for item in body.pop("repairs", []):
            if item.get("finding_id"):
                db.execute(
                    "INSERT INTO finding_repairs VALUES(?,?,?)",
                    (sid, item["finding_id"], encoded(item)),
                )
        if repair:
            db.execute("INSERT INTO repairs VALUES(?,?)", (sid, encoded(repair)))
        db.execute(
            "UPDATE scans SET status=?,result=? WHERE id=?",
            (result["status"], encoded(body), sid),
        )
        db.execute("UPDATE jobs SET state='done' WHERE scan=?", (sid,))
        event(db, sid, result["status"])


def detail(sid):
    with database() as db:
        row = db.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise KeyError("Unknown scan")
        repair = db.execute("SELECT data FROM repairs WHERE scan=?", (sid,)).fetchone()
        findings = [
            json.loads(r[0])
            for r in db.execute("SELECT data FROM findings WHERE scan=? ORDER BY ordinal", (sid,))
        ]
        if not findings and row["status"] in (
            "running",
            "capturing",
            "deciding",
            "interrupted",
        ):
            findings = [
                json.loads(r[0])
                for r in db.execute("SELECT data FROM previews WHERE scan=? ORDER BY rowid", (sid,))
            ]
        job = dict(db.execute("SELECT state,attempts FROM jobs WHERE scan=?", (sid,)).fetchone())
        transitions = [
            dict(t)
            for t in db.execute("SELECT * FROM transitions WHERE scan=? ORDER BY id", (sid,))
        ]
        req = json.loads(row["request"])
        stage = {
            "capturing": "Determining changed files",
            "queued": "Waiting for worker",
            "running": "Checking selected files",
            "deciding": "Checking outgoing commits",
            "interrupted": "Recovery required",
        }.get(row["status"], "Review finished")
        recovery = None
        if row["status"] == "interrupted":
            recovery = (
                "Retry the Git push to recheck current refs"
                if req.get("trigger") == "pre-push"
                else "Start a new capture"
                if req.get("pid") and "task_status" not in req
                else "Retry this scan"
            )
        return {
            "scope": None,
            "coverage": {},
            "issues": [],
            "next_stage": stage,
            "recovery": recovery,
            "last_successful_observation": next(
                (
                    t
                    for t in reversed(transitions)
                    if t["state"]
                    in (
                        "property-confirmed",
                        "checked-negative",
                        "fixed",
                        "restored",
                        "candidate",
                        "verified",
                        "staged",
                        "committed",
                    )
                ),
                None,
            ),
            "last_observation": dict(
                db.execute(
                    "SELECT * FROM events WHERE scan=? ORDER BY id DESC LIMIT 1", (sid,)
                ).fetchone()
            ),
            "repairs": [
                json.loads(r[0])
                for r in db.execute(
                    "SELECT data FROM finding_repairs WHERE scan=? ORDER BY rowid",
                    (sid,),
                )
            ],
            "transitions": transitions,
            "counts_summary": counters(findings, transitions),
            **req,
            **json.loads(row["result"] or "{}"),
            "id": sid,
            "created": row["created"],
            "status": row["status"],
            "job": job,
            "findings": findings,
            "repair": json.loads(repair[0]) if repair else None,
            "push_reviews": [
                json.loads(r[0])
                for r in db.execute(
                    "SELECT data FROM push_evidence WHERE scan=? ORDER BY rowid", (sid,)
                )
            ],
        }


def listing():
    result = []
    with database() as db:
        counts = {}
        for sid, category, n in db.execute(
            "SELECT scan,json_extract(data,'$.category'),count(*) FROM findings GROUP BY 1,2"
        ):
            counts.setdefault(sid, {})[category] = n
        for row in db.execute("""SELECT id,created,status,repo,json_extract(request,'$.trigger') AS trigger,
                json_extract(request,'$.snapshot.sha256') AS sha,json_extract(result,'$.coverage') AS coverage
                FROM scans ORDER BY created DESC,id"""):
            result.append(
                dict(
                    id=row["id"],
                    created=row["created"],
                    status=row["status"],
                    trigger=row["trigger"],
                    snapshot={"repository": row["repo"], "sha256": row["sha"]},
                    coverage=json.loads(row["coverage"] or "{}"),
                    counts=counts.get(row["id"], {}),
                )
            )
        for r in result:
            fs = [
                json.loads(f[0])
                for f in db.execute("SELECT data FROM findings WHERE scan=?", (r["id"],))
            ]
            ts = db.execute(
                "SELECT finding,state FROM transitions WHERE scan=?", (r["id"],)
            ).fetchall()
            r["counts_summary"] = counters(fs, ts)
    return result


def events(after):
    with database() as db:
        return [
            dict(row)
            for row in db.execute("SELECT * FROM events WHERE id>? ORDER BY id LIMIT 200", (after,))
        ]


def transition(db, sid, fid, state, reason, actor="system"):
    db.execute(
        "INSERT INTO transitions(scan,finding,state,reason,actor,time) VALUES(?,?,?,?,?,?)",
        (
            sid,
            fid,
            state,
            TOKEN.sub("[redacted]", reason),
            TOKEN.sub("[redacted]", actor),
            time.time(),
        ),
    )


def dismiss(sid, fid, actor, reason, false_positive=False):
    if not actor.strip() or not reason.strip():
        raise ValueError("Provide an actor and a reason")
    with database() as db:
        if not db.execute(
            "SELECT 1 FROM findings WHERE scan=? AND json_extract(data,'$.id')=?", (sid, fid)
        ).fetchone():
            raise KeyError("Unknown finding")
        transition(db, sid, fid, "dismissed", reason, actor)
        if false_positive:
            transition(db, sid, fid, "adjudicated false positive", reason, actor)
        event(db, sid, "finding dismissed")


def counters(findings, transitions):
    severity = dict.fromkeys(("Critical", "P2", "P3", "P4"), 0)
    for f in findings:
        key = "Critical" if f["severity"] == "P1" else f["severity"]
        severity[key] = severity.get(key, 0) + 1
    return dict(
        caught=len(findings),
        confirmed=sum(h.get("state") in ("property-confirmed", "verified") for h in findings),
        applied=len({t["finding"] for t in transitions if t["state"] == "fixed"}),
        adjudicated_false_positives=len(
            {t["finding"] for t in transitions if t["state"] == "adjudicated false positive"}
        ),
        severity=severity,
    )


def demo_home():
    base = home()
    if base.name == "demo-replay-v2" and (base / ".laundromat-demo").is_file():
        return base
    folder = base / "demo-replay-v2"
    marker = folder / ".laundromat-demo"
    if folder.is_symlink() or (folder.exists() and not marker.is_file()):
        raise ValueError("Expected a marked synthetic ledger")
    folder.mkdir(mode=0o700, exist_ok=True, parents=True)
    marker.touch(exist_ok=True)
    return folder


def seed_demo_history(*, reseed=False):
    from .scenarios import SCENARIOS, examples, measure

    root = demo_home()
    token = LEDGER.set(root)
    try:
        missing = [tool for tool in ("gitleaks", "semgrep", "docker") if not shutil.which(tool)]
        if missing:
            raise ValueError(f"Required tools not found: {', '.join(missing)}. Install them before seeding the demo ledger.")
        for scenario in SCENARIOS:
            for label, before, files in examples(scenario):
                identity = {p: digest(v) for p, v in files.items()}
                key = digest(
                    json_bytes(
                        [scenario, label, identity, {p: digest(v) for p, v in before.items()}]
                    )
                )
                req = dict(
                    trigger="demo replay",
                    provenance="demo replay",
                    fixture=label,
                    scenario=scenario,
                    snapshot=dict(
                        repository="synthetic/" + scenario, files=identity, issues=[], sha256=key
                    ),
                    scope=sorted(files),
                )
                sid = submit(req, "demo-v2/" + key, state="importing")
                if reseed or detail(sid)["job"]["state"] != "done":
                    result = measure(before, files)
                    if result.get("verified_actions"):
                        if label == "SQL binding":
                            replay_rollback(files, result)
                        result["replayed_actions"] = result["verified_actions"]
                        result["verified_actions"] = []
                    finish(sid, result, refresh_demo=reseed)
        rows = listing()
        with database() as db:
            injection_ids = [r[0] for r in db.execute(
                "SELECT id FROM scans WHERE json_extract(request,'$.scenario')='injection' ORDER BY created,id"
            )]
        return {
            "ledger": str(root),
            "scans": len(rows),
            "findings": sum(r["counts_summary"]["caught"] for r in rows),
            "provenance": "demo replay",
            "demo_url": "http://localhost:8731",
            "injection_scan_ids": injection_ids,
        }
    finally:
        LEDGER.reset(token)


def observe_once(db, sid, fid, state, reason):
    if not db.execute(
        "SELECT 1 FROM transitions WHERE scan=? AND finding=? AND state=?", (sid, fid, state)
    ).fetchone():
        transition(db, sid, fid, state, reason)


def progress(sid, finding):
    with database() as db:
        db.execute(
            "INSERT OR REPLACE INTO previews VALUES(?,?,?)", (sid, finding["id"], encoded(finding))
        )
        state = finding.get("state", "candidate")
        observe_once(db, sid, finding["id"], state, finding.get("property", finding["explanation"]))
        event(db, sid, state)


def replay_rollback(files, result):
    import tempfile
    from . import repair
    from .snapshot import snapshot

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        repo = root / "repo"
        repo.mkdir()
        for path, data in files.items():
            (repo / path).write_bytes(data)
        token = LEDGER.set(root / "ledger")
        try:
            snap, _ = snapshot(repo)
            sid = submit(
                dict(trigger="synthetic rollback verification", snapshot=snap, scope=sorted(files))
            )
            finish(sid, result)
            applied = repair.change(sid, False)
            restored = repair.change(sid, True)
            if restored["sha256"] != snap["files"]["search.js"]:
                raise ValueError("Replay rollback hash mismatch")
            observed = detail(sid)
            result["replayed_transitions"] = [
                t for t in observed["transitions"] if t["state"] in ("fixed", "restored")
            ]
            result["rollback_observation"] = {
                "applied_sha256": applied["sha256"],
                "restored_sha256": restored["sha256"],
                "receipt_sha256": digest(json_bytes(observed)),
            }
            result["repair"].update(
                state="restored", restored_sha256=restored["sha256"], application_actor="developer"
            )
        finally:
            LEDGER.reset(token)
