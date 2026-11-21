"""Stage an entire verified proposal with one Git index transaction."""

import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

from . import history, inventory
from .snapshot import git
from .workspace import digest, plain


@contextmanager
def repository_lock(repo):
    folder = history.home()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if fcntl is None:
        yield
        return
    with (folder / ("push-" + digest(os.fsencode(repo)) + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def evidence(db, sid, item):
    db.execute(
        "INSERT OR REPLACE INTO push_evidence VALUES(?,?,?)",
        (sid, item["finding_id"], history.encoded(item)),
    )
    history.observe_once(
        db, sid, item["finding_id"], item["state"], item.get("reason") or item["state"]
    )
    history.event(db, sid, item["state"])


def record(sid, item):
    with history.database() as db:
        evidence(db, sid, item)


def apply(sid, *, automatic=False, finding=None):
    scan = history.detail(sid)
    repo = Path(scan["snapshot"]["repository"])
    if scan["trigger"] != "pre-push":
        raise ValueError("Approval requires a pre-push receipt")
    if automatic:
        # The hook already holds the repository lock.
        return stage(repo, scan, automatic=True)
    with repository_lock(repo):
        return stage(repo, history.detail(sid), automatic=False, finding=finding)


def stage(repo, scan, *, automatic, finding=None):
    proposals = [item for item in scan["push_reviews"] if item.get("verified")]
    if finding is not None:
        proposals = [p for p in proposals if p["finding_id"] == finding]
    if not proposals or not scan.get("proposal_ready"):
        raise ValueError("This receipt has no stageable verified proposal")
    branch = git(repo, "symbolic-ref", "-q", "HEAD", check=False).decode().strip()
    updates = scan["updates"]
    if automatic and len(updates) != 1:
        raise ValueError("Multi-ref push requires manual assignment")
    tip = git(repo, "rev-parse", "--verify", "HEAD").decode().strip()
    if not any(
        branch
        and u["local"] in (branch, "HEAD")
        and u["remote"].startswith("refs/heads/")
        and u["tip"] == tip
        for u in updates
    ):
        raise ValueError("Stale proposal or reviewed branch is not checked out")
    proposals = [p for p in proposals if p["commit"] == tip]
    if not proposals:
        raise ValueError("No verified repair belongs to the checked-out commit")

    if len(proposals) != 1 or proposals[0]["path"] != inventory.SOURCE:
        raise ValueError("Conflicting or out-of-scope repair; stage nothing")
    p = proposals[0]
    path = p["path"]
    if not git(repo, "ls-tree", tip, "--", path).startswith(b"100644 blob "):
        raise ValueError("Unsupported source file mode")
    original = git(repo, "show", tip + ":" + path)
    candidate = p["candidate"].encode()
    patch = inventory.diff(path, original, candidate)
    if (
        not inventory.approved(candidate)
        or digest(original) != p["original_sha256"]
        or digest(candidate) != p["candidate_sha256"]
        or digest(patch.encode()) != p["patch_sha256"]
    ):
        raise ValueError("Stale proposal bytes or patch digest")
    entries = git(repo, "ls-files", "-s", "--", path).splitlines()
    if len(entries) != 1 or not entries[0].startswith(b"100644 ") or b" 0\t" not in entries[0]:
        raise ValueError("Conflicting index entry or file mode")
    indexed = git(repo, "show", ":" + path)
    target = plain(repo / path)
    if target.stat().st_size > 2_000_000 or len(indexed) > 2_000_000:
        raise ValueError("Local file exceeds staging limit")
    working = target.read_bytes()
    intent = p.get("staging_intent")
    if intent and digest(indexed) == intent["after"]:
        # A repeated approval or a crash after Git acquired and committed its index lock.
        applied = intent["diff"]
    else:
        if p["state"] in ("staged", "committed"):
            raise ValueError("Previously staged proposal changed; review current index")
        old_lines, new_lines = original.splitlines(True), candidate.splitlines(True)
        changes = [(a, b) for a, b in zip(old_lines, new_lines) if a != b]
        if len(changes) != 1 or len(old_lines) != len(new_lines):
            raise ValueError("Expected a single verified statement replacement")
        old, new = changes[0]

        def project(data):
            lines = data.splitlines(True)
            if lines.count(old) != 1 or new in lines:
                raise ValueError("Repair overlaps local edits or has an ambiguous preimage")
            lines[lines.index(old)] = new
            return b"".join(lines)

        staged_bytes, working_bytes = project(indexed), project(working)
        # Refuse if a local edit moved the target into a different function or removed
        # its surrounding declaration. Blank lines and additions outside the export are safe.
        for data in (indexed, working):
            if data != original and original.strip() not in data:
                raise ValueError("Affected declaration has local edits; proposal retained")
        index_patch = inventory.diff(path, indexed, staged_bytes)
        work_patch = inventory.diff(path, working, working_bytes)
        # Store only the verified statement when surrounding local bytes are private.
        applied = (
            patch if indexed == original else inventory.diff(path, indexed, staged_bytes, context=0)
        )
        p["staging_intent"] = dict(before=digest(indexed), after=digest(staged_bytes), diff=applied)
        record(scan["id"], p)
        if os.getenv("GIT_INDEX_FILE"):
            raise ValueError("Alternate Git index requires manual review")
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")
        }

        def git_apply(args, text):
            return subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "core.fsmonitor=false",
                    "apply",
                    "--whitespace=nowarn",
                    *args,
                    "-",
                ],
                input=text.encode(),
                capture_output=True,
                env=env,
                timeout=15,
            ).returncode

        if git(repo, "rev-parse", "HEAD").decode().strip() != tip or target.read_bytes() != working:
            raise ValueError("Checkout changed during approval")
        if working == indexed:
            if git_apply(["--index"], index_patch):
                raise ValueError("Git could not apply the hunk to the index and working tree")
        else:
            if git_apply(["--check"], work_patch) or git_apply(["--cached"], index_patch):
                raise ValueError("Git could not stage the verified hunk")
            if git_apply([], work_patch):
                p["working_tree_issue"] = (
                    "Index staged; working tree changed concurrently and needs review"
                )
        if digest(git(repo, "show", ":" + path)) != digest(staged_bytes):
            raise ValueError("Index changed while recording the staged hunk")
    if p["state"] != "staged":
        p.update(
            state="staged",
            staged_diff=applied,
            staging_actor="vibe-coder" if automatic else "developer",
        )
        record(scan["id"], p)
    return dict(
        scan=scan["id"],
        state="staged",
        paths=[path],
        next=p.get("working_tree_issue")
        or "Review the staged diff, commit the repair, then push again.",
    )


def observe_commits(repo, updates):
    """Record a later commit containing the exact staged repair on the reviewed branch."""
    with history.database() as db:
        rows = db.execute(
            """SELECT e.scan,e.data,s.request FROM push_evidence e
            JOIN scans s ON s.id=e.scan WHERE s.repo=? AND json_extract(e.data,'$.state')='staged'""",
            (str(repo),),
        ).fetchall()
        for row in rows:
            p, request = json.loads(row["data"]), json.loads(row["request"])
            for u in updates:
                tip = u["tip"]
                if (
                    not tip.strip("0")
                    or tip == p["commit"]
                    or not any(
                        old["local"] == u["local"] and old["tip"] == p["commit"]
                        for old in request["updates"]
                    )
                ):
                    continue
                merge_base = git(repo, "merge-base", tip, p["commit"], check=False).decode().strip()
                if merge_base == p["commit"] and digest(
                    git(repo, "show", tip + ":" + p["path"], check=False)
                ) == p.get("staging_intent", {}).get("after", p["candidate_sha256"]):
                    p.update(state="committed", committed_oid=tip)
                    evidence(db, row["scan"], p)
                    break
