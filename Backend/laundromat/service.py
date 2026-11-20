import json
import os
import time

try:
    import fcntl as _fcntl

    def _flock(lock):
        _fcntl.flock(lock, _fcntl.LOCK_EX)

except ImportError:  # Windows
    def _flock(lock):
        pass  # skip advisory file locking on Windows

from . import history
from .snapshot import snapshot, git


def format_cli_summary(result, logs):
    """Build a concise CLI-style log string to surface in the dashboard terminal."""
    lines = list(logs)  # progress lines captured during the scan
    lines.append("")
    lines.append("\u2500" * 50)
    findings = result.get("findings", [])
    if findings:
        lines.append(f"\u26a0  {len(findings)} finding(s) detected:")
        for f in findings:
            sev = "Critical" if f.get("severity") == "P1" else f.get("severity", "?")
            loc = f.get("path", "?") + (f":{f['line']}" if f.get("line") else "")
            lines.append(f"  [{sev}] {f.get('category','?')} \u00b7 {loc}")
            expl = f.get("explanation", "")
            if expl:
                lines.append(f"           {expl[:120]}")
    else:
        lines.append("\u2713  No findings \u2014 scan clean")
    elapsed = result.get("elapsed_ms")
    status = result.get("status", "unknown")
    if elapsed is not None:
        lines.append(f"\nCompleted in {elapsed} ms \u00b7 status: {status}")
    return "\n".join(lines)


def enqueue(repo, scope=None, key=None, trigger="local snapshot", model=False, category=None):
    snap, initial = snapshot(repo, scope)
    if scope and any(n.endswith("package.json") for n in initial):
        snap, _ = snapshot(repo)
    request = dict(
        trigger=trigger,
        snapshot=snap,
        scope=sorted(scope or snap["files"]),
        category=category,
        full_context=not scope or any(n.endswith("package.json") for n in initial),
        model=model,
    )
    return history.submit(request, key)


def recover(db):
    for row in db.execute(
        "SELECT scan,state FROM jobs WHERE state IN ('running','capturing','deciding')"
    ).fetchall():
        sid = row["scan"]
        if row["state"] in ("capturing", "deciding"):
            request = json.loads(
                db.execute("SELECT request FROM scans WHERE id=?", (sid,)).fetchone()[0]
            )
            try:
                if request.get("pid"):
                    os.kill(request["pid"], 0)
                    continue
            except ProcessLookupError:
                pass
        db.execute("UPDATE jobs SET state='interrupted' WHERE scan=?", (sid,))
        db.execute("UPDATE scans SET status='interrupted' WHERE id=?", (sid,))
        history.event(db, sid, "interrupted")


def retry(sid):
    with history.database() as db:
        row = db.execute("SELECT state FROM jobs WHERE scan=?", (sid,)).fetchone()
        if not row or row[0] != "interrupted":
            raise ValueError("Only an interrupted job can be retried")
        req = json.loads(db.execute("SELECT request FROM scans WHERE id=?", (sid,)).fetchone()[0])
        if req.get("trigger") == "pre-push":
            raise ValueError("Retry the Git push with fresh outgoing refs")
        if req.get("pid") and "task_status" not in req:
            raise ValueError(
                "Interrupted capture retained its before snapshot. Start a new task to capture a new delta."
            )
        db.execute("UPDATE jobs SET state='queued' WHERE scan=?", (sid,))
        db.execute("UPDATE scans SET status='queued' WHERE id=?", (sid,))
        history.event(db, sid, "retried")


def work(sid=None, progress_callback=None):
    from .pipeline import inspect

    history.home().mkdir(mode=0o700, parents=True, exist_ok=True)
    with (history.home() / "worker.lock").open("a") as lock:
        _flock(lock)
        with history.database() as db:
            recover(db)
            row = db.execute(
                "SELECT scan FROM jobs WHERE state='queued' AND (? IS NULL OR scan=?) ORDER BY rowid LIMIT 1",
                (sid, sid),
            ).fetchone()
            if row is None:
                return None
            sid = row[0]
            db.execute("UPDATE jobs SET state='running',attempts=attempts+1 WHERE scan=?", (sid,))
            db.execute("UPDATE scans SET status='running' WHERE id=?", (sid,))
            history.event(db, sid, "running")
        req = history.detail(sid)
        start = time.time()
        logs: list[str] = []

        def _capture(msg):
            logs.append(str(msg))
            if progress_callback:
                progress_callback(msg)

        try:
            current, files = snapshot(
                req["snapshot"]["repository"], list(req["snapshot"]["files"]), allow_absent=True
            )
            if (
                current["files"] != req["snapshot"]["files"]
                or current["revision"] != req["snapshot"]["revision"]
                or current["directory_id"] != req["snapshot"]["directory_id"]
            ):
                raise ValueError("Queued snapshot no longer matches the selected files or revision")
            req["progress_id"] = sid
            selected = {name: files[name] for name in req["scope"] if name in files}
            manifests = [n for n in selected if n.rsplit("/", 1)[-1] == "package.json"]
            if manifests:
                rev = current["revision"]
                base = (
                    {
                        n: git(current["repository"], "show", rev + ":" + n, check=False) or b"{}"
                        for n in manifests
                    }
                    if rev
                    else {}
                )
                result = inspect(
                    dict(req, baseline_known=bool(rev)),
                    selected,
                    before_files=base,
                    context_files=files,
                    progress_callback=_capture,
                )
            else:
                result = inspect(req, selected, progress_callback=_capture)
        except Exception as exc:
            result = dict(
                status="incomplete",
                coverage={},
                findings=[],
                issues=[f"Worker: {type(exc).__name__}: {exc}"],
            )
        result["elapsed_ms"] = round((time.time() - start) * 1000)
        if "task_finished" in req:
            result["task_to_verdict_ms"] = round((time.time() - req["task_finished"]) * 1000)
        result["cli_log"] = format_cli_summary(result, logs)
        history.finish(sid, result)
        return sid
