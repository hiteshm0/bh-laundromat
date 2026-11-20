"""Stage bounded unified diffs and wrapper-returned fixture edits in memory."""

import difflib
import re
import hashlib
import json
import stat
from pathlib import Path

from . import history, pipeline, repair
from .snapshot import LIMIT, delta, relative, snapshot, trusted
from .workspace import SEARCH, atomic_write, digest, json_bytes, plain


def patched(files, data):
    if len(data) > LIMIT or b"\x00" in data:
        raise ValueError("Binary or oversized diff")
    lines = data.splitlines(keepends=True)
    result, touched = dict(files), []
    i = 0
    index = None
    while i < len(lines):
        if lines[i].startswith(b"index "):
            match = re.fullmatch(
                rb"index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})(?: 100(?:644|755))?\n?", lines[i]
            )
            if not match:
                raise ValueError("Unsupported blob index")
            index = tuple(v.decode() for v in match.groups())
            i += 1
            continue
        if lines[i].startswith((b"diff --git ", b"new file mode ", b"deleted file mode ")):
            i += 1
            continue
        if (
            not lines[i].startswith(b"--- ")
            or i + 1 >= len(lines)
            or not lines[i + 1].startswith(b"+++ ")
        ):
            raise ValueError("Expected unified file headers")
        left, right = [row[4:].rstrip(b"\r\n").decode() for row in lines[i : i + 2]]
        if (left != "/dev/null" and not left.startswith("a/")) or (
            right != "/dev/null" and not right.startswith("b/")
        ):
            raise ValueError("Expected relative a/ and b/ paths")
        old = None if left == "/dev/null" else relative(left[2:])
        new = None if right == "/dev/null" else relative(right[2:])
        path = new or old
        if (
            not path
            or (old and new and old != new)
            or path in touched
            or (old is None) == (path in files)
        ):
            raise ValueError("Unsupported rename, duplicate or stale file preimage")
        if b"\0" in files.get(path, b"") or len(touched) >= 128:
            raise ValueError("Binary preimage or excessive changed paths")
        touched.append(path)
        source, output, pos = files.get(path, b"").splitlines(True), [], 0
        i += 2
        hunks = 0
        while i < len(lines) and lines[i].startswith(b"@@ "):
            m = re.fullmatch(rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?", lines[i])
            if not m:
                raise ValueError("Malformed diff hunk")
            a, n, b, count = [int(v) if v is not None else 1 for v in m.groups()]
            start = a - int(n > 0)
            if start < pos or start > len(source):
                raise ValueError("Stale preimage offset")
            output.extend(source[pos:start])
            if b - int(count > 0) != len(output):
                raise ValueError("Invalid postimage offset")
            pos, removed, added = start, 0, 0
            i += 1
            hunks += 1
            while removed < n or added < count:
                if i >= len(lines) or lines[i][:1] not in (b" ", b"+", b"-"):
                    raise ValueError("Truncated diff")
                op, content = lines[i][:1], lines[i][1:]
                i += 1
                if i < len(lines) and lines[i].rstrip() == b"\\ No newline at end of file":
                    content = content.removesuffix(b"\n")
                    i += 1
                if op != b"+":
                    if pos >= len(source) or source[pos] != content:
                        raise ValueError("Stale diff preimage")
                    pos += 1
                    removed += 1
                if op != b"-":
                    output.append(content)
                    added += 1
            if (removed, added) != (n, count):
                raise ValueError("Diff hunk length mismatch")
        if not hunks:
            raise ValueError("Expected a text hunk")
        after = b"".join(output + source[pos:])
        if len(after) > LIMIT or (new is None and after):
            raise ValueError("Invalid diff result")
        if index:

            def matches(data, oid, absent):
                if absent:
                    return not oid.strip("0")
                blob = f"blob {len(data)}\0".encode() + data
                return any(
                    hashlib.new(alg, blob).hexdigest().startswith(oid) for alg in ("sha1", "sha256")
                )

            if not matches(files.get(path, b""), index[0], old is None) or not matches(
                after, index[1], new is None
            ):
                raise ValueError("Stale blob identity")
            index = None
        if new is None:
            del result[path]
        else:
            result[path] = after
    if not touched:
        raise ValueError("No text changes")
    return result, touched


def compare(req, old, new, paths, progress_callback=None):
    before = pipeline.inspect(
        {**req, "baseline_known": True},
        {p: old[p] for p in paths if p in old},
        before_files=old,
        context_files=old,
        verify=False,
    )
    after = pipeline.inspect(
        {**req, "baseline_known": True},
        {p: new[p] for p in paths if p in new},
        before_files=old,
        context_files=new,
        progress_callback=progress_callback,
    )
    remaining = list(before["findings"])
    positions = {}
    for path in paths:
        a, b = old.get(path, b"").splitlines(), new.get(path, b"").splitlines()
        positions[path] = {
            i + offset + 1: j + offset + 1
            for i, j, n in difflib.SequenceMatcher(None, a, b, autojunk=True).get_matching_blocks()
            for offset in range(n)
        }
    for hit in after["findings"]:
        prior = next(
            (
                h
                for h in remaining
                if (h["path"], h["rule"]) == (hit["path"], hit["rule"])
                and (
                    (h["line"] is None and hit["line"] is None and h["evidence"] == hit["evidence"])
                    or (
                        h["line"] is not None and positions[h["path"]].get(h["line"]) == hit["line"]
                    )
                )
            ),
            None,
        )
        hit["change"] = "introduced" if prior is None else "pre-existing"
        if prior is not None:
            remaining.remove(prior)
    after["removed_matches"] = remaining
    after["baseline_coverage"] = before["coverage"]
    if before["issues"]:
        after["issues"].extend("Baseline: " + reason for reason in before["issues"])
        after.update(status="incomplete", verified_actions=[])
    return after


def stage(sid, req, old, candidate):
    new = dict(old, **{SEARCH: candidate})
    base = req["snapshot"]
    proposed = {**base, "files": {**base["files"], SEARCH: digest(candidate)}}
    proposed["sha256"] = digest(json_bytes(proposed["files"]))
    result = compare(req, old, new, [SEARCH])
    result.update(
        scope=[SEARCH],
        proposed_snapshot=proposed,
        changes=delta(base, proposed, old, new),
        proposal_state="pending",
        trigger="wrapper pre-write proposal",
        backup_reference=sid + ".working",
        proposed_reference=sid + ".proposed",
    )
    for ext, data in (("working", old[SEARCH]), ("proposed", candidate)):
        if not trusted(data):
            raise ValueError("Only owned fixture bytes can be saved for acceptance")
        atomic_write(history.home() / (sid + "." + ext), data)
    history.finish(sid, result)


def decide(sid, action, actor="developer"):
    record = history.detail(sid)
    with history.database() as db:
        row = db.execute("SELECT result FROM scans WHERE id=?", (sid,)).fetchone()
        body = json.loads(row[0] or "{}")
        state = body.get("proposal_state")
        if (action == "undo" and state != "accepted") or (action != "undo" and state != "pending"):
            raise ValueError("Proposal decision is stale")
        if action == "reject":
            if (history.home() / (sid + ".proposal-operation")).exists():
                raise ValueError("Resume the interrupted acceptance decision first")
            body["proposal_state"] = "rejected"
        else:
            if action not in ("accept", "undo") or body.get("status") == "incomplete":
                raise ValueError("Incomplete proposal cannot be accepted")
            base = record["snapshot"]
            current, files = snapshot(base["repository"])
            working = plain(history.home() / (sid + ".working")).read_bytes()
            proposed = plain(history.home() / (sid + ".proposed")).read_bytes()
            if (
                digest(working) != base["files"][SEARCH]
                or digest(proposed) != body["proposed_snapshot"]["files"][SEARCH]
                or not trusted(working)
                or not trusted(proposed)
            ):
                raise ValueError("Proposal backup integrity failure")
            r = record["repair"]
            if r:
                fixed = r["candidate"].encode()
                if (
                    not record["verified_actions"]
                    or digest(fixed) != r["candidate_sha256"]
                    or fixed != repair.fix(proposed, r["line"])
                    or r["original_sha256"] != digest(proposed)
                ):
                    raise ValueError("No applicable verified candidate")
            else:
                from .snapshot import SAFE_HASH

                if digest(proposed) != SAFE_HASH or record["findings"]:
                    raise ValueError("Proposal requires manual review")
                fixed = proposed
            expected, target = (fixed, working) if action == "undo" else (working, fixed)
            journal = history.home() / (sid + ".proposal-operation")
            operation = json_bytes(
                dict(
                    action=action,
                    from_state=state,
                    original=digest(expected),
                    destination=digest(target),
                )
            )
            resumed = (
                current["files"].get(SEARCH) == digest(target)
                and journal.exists()
                and plain(journal).read_bytes() == operation
            )
            expected_files = {**base["files"], SEARCH: digest(target if resumed else expected)}
            if (
                current["directory_id"] != base["directory_id"]
                or current["revision"] != base["revision"]
                or current["files"] != expected_files
                or current["issues"]
            ):
                raise ValueError("Stale proposal base or concurrent edit")
            path = plain(Path(base["repository"]) / SEARCH)
            if path.read_bytes() != (target if resumed else expected):
                raise ValueError("Concurrent edit")
            if not resumed:
                atomic_write(journal, operation)
                if plain(path).read_bytes() != expected:
                    raise ValueError("Concurrent edit")
                atomic_write(path, target, stat.S_IMODE(path.stat().st_mode))
            body.update(
                proposal_state="restored" if action == "undo" else "accepted",
                working_sha256=digest(target),
                application_actor=actor,
                undo_command="laundromat undo " + sid,
            )
            if r:
                r.update(
                    state="restored" if action == "undo" else "applied",
                    application_actor=actor,
                    backup_reference=sid + ".working",
                    restored_sha256=digest(target) if action == "undo" else None,
                )
                for h in record["findings"]:
                    if h.get("state") == "property-confirmed" and h["path"] == r["path"]:
                        history.transition(
                            db,
                            sid,
                            h["id"],
                            "restored" if action == "undo" else "fixed",
                            r["property"],
                            actor,
                        )
                if r.get("finding_id"):
                    db.execute(
                        "UPDATE finding_repairs SET data=? WHERE scan=? AND finding=?",
                        (history.encoded(r), sid, r["finding_id"]),
                    )
                db.execute("UPDATE repairs SET data=? WHERE scan=?", (history.encoded(r), sid))
        db.execute("UPDATE scans SET result=? WHERE id=?", (history.encoded(body), sid))
        history.event(db, sid, "proposal " + body["proposal_state"])
    return history.detail(sid)
