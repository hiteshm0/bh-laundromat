"""Fix proposes bytes. Verify runs trusted checks. Only the controller authorizes changes."""

import json
import stat
import tempfile
import time
from pathlib import Path

from . import history, provider
from .checks import check
from .sandbox import suite_digest
from .review import REPLACEMENT, diff, template, verdict
from .snapshot import HEADER, ORIGINAL_HASH, SAFE_HASH, git, trusted
from .workspace import FIXTURE, SEARCH, CONTROL, atomic_write, digest, plain, json_bytes


def fix(original, line, answer=None):
    baseline = template(original, line)
    if answer is None:
        return baseline
    if (
        not isinstance(answer, dict)
        or set(answer) != {"path", "replacement"}
        or answer["path"] != SEARCH
    ):
        raise ValueError("Candidate must edit the one search expression in search.js")
    options = (REPLACEMENT, REPLACEMENT.replace(b'"', b"'"))
    if not isinstance(answer["replacement"], str):
        raise ValueError("Expected a replacement expression string")
    replacement = answer["replacement"].encode()
    if replacement not in options:
        raise ValueError("Candidate expression is outside the validated shape")
    return baseline.replace(REPLACEMENT, replacement, 1)


def verify(original, candidate, origin, line, before=None):
    if not trusted(original) or not trusted(candidate):
        raise ValueError("Unsupported fixture bytes")
    start = time.monotonic()
    control = (FIXTURE / "fixture" / CONTROL).read_bytes()
    if digest(control) != SAFE_HASH:
        raise ValueError("Trusted negative control changed")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture"
        path.mkdir()
        (path / CONTROL).write_bytes(control)
        (path / SEARCH).write_bytes(original)
        before = before or check(path)
        (path / SEARCH).write_bytes(candidate)
        after = check(path)
    patch = diff(original, candidate)
    result = dict(
        property="parameter binding",
        suite="phase1-binding-v1",
        origin=origin,
        sandbox=before["binding"].get("attempt", before["binding"]).get("runtime"),
        suite_digest=suite_digest(),
        path=SEARCH,
        line=line,
        original_sha256=digest(original),
        candidate_sha256=digest(candidate),
        candidate=candidate.decode(),
        diff=patch.decode(),
        patch_sha256=digest(patch),
        before=before,
        after=after,
        state="candidate",
        elapsed_ms=round((time.monotonic() - start) * 1000),
    )
    result["verdict"], result["reason"] = verdict(
        dict(
            before=before,
            after=after,
            snapshot={"files": {CONTROL: digest(control), SEARCH: digest(original)}},
            repair=result,
        )
    )
    return result


def propose(data, finding, use_model, *, fallback=True, model_context=None):
    if digest(data.removeprefix(HEADER)) != ORIGINAL_HASH or finding["path"] != SEARCH:
        finding["repair_status"] = "unsupported fixture or query style"
        return None
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / SEARCH).write_bytes(data)
        (root / CONTROL).write_bytes((FIXTURE / "fixture" / CONTROL).read_bytes())
        before = check(root)
    finding["original_observations"] = before
    if (
        before["binding"]["status"] != "fail"
        or before["semgrep"].get("negative_control") != "pass"
        or before["sqlite"]["status"] != "pass"
    ):
        finding["repair_status"] = "original property check incomplete or negative"
        return None
    origin, explanation, issue, usage, model = "template", None, None, None, None
    candidate = fix(data, finding["line"])
    if use_model:
        attempt = {"proposed": False, "usage": None, "model": None}
        finding["model_attempt"] = attempt
        try:
            answer = provider.ask(
                model_context if model_context is not None else {SEARCH: data.decode()}, "C"
            )
            attempt.update(
                proposed=answer["candidate"] is not None,
                usage=answer["usage"],
                model=answer["model"],
            )
            if answer["candidate"] is None:
                raise ValueError("Model proposed no candidate")
            candidate = fix(data, finding["line"], answer["candidate"])
            origin, explanation, usage = "model", answer["explanation"], answer["usage"]
            model = answer["model"]
        except (ValueError, AttributeError) as exc:
            issue = str(exc)
            attempt["reason"] = issue
            if not fallback:
                finding["repair_status"] = "no validated model candidate"
                return None
    result = verify(data, candidate, origin, finding["line"], before)
    result.update(model_issue=issue, model_explanation=explanation, usage=usage, model=model)
    finding["repair_status"] = result["verdict"] + " parameter binding"
    return result


def change(sid, undo, finding_id=None):
    # Serialize operations against the same ledger, including writes from other CLI processes.
    scan = history.detail(sid)
    if scan.get("provenance") == "demo replay":
        raise ValueError("Historical demo replay is read-only")
    if scan.get("proposal_state"):
        from .proposal import decide

        if not undo:
            raise ValueError("Use laundromat accept for a reviewed agent proposal")
        return decide(sid, "undo")
    if scan["status"] == "incomplete" or (
        "verified_actions" in scan and not scan["verified_actions"]
    ):
        raise ValueError("No applicable verified repair")
    with history.database() as db:
        row = db.execute("SELECT data FROM repairs WHERE scan=?", (sid,)).fetchone()
        primary = json.loads(row[0]) if row else {}
        if finding_id:
            row = db.execute(
                "SELECT data FROM finding_repairs WHERE scan=? AND finding=?", (sid, finding_id)
            ).fetchone()
        if not row:
            raise ValueError("No verified repair for this scan")
        r = json.loads(row[0])
        if r.get("imported"):
            raise ValueError("Use the originating receipt for an imported repair")
        fid = r.get("finding_id")
        if fid and not any(
            action.get("finding_id") == fid for action in scan.get("verified_actions", [])
        ):
            raise ValueError("No applicable verified action for this finding")
        test = r.get("test_id")
        if test:
            from . import owned, sandbox

            item = sandbox.OWNED[test]
            if (
                r["verdict"] != "verified"
                or r["path"] != item["path"]
                or r["original_sha256"] != digest(sandbox.owned_bytes(test, "before"))
                or r["candidate_sha256"] != digest(sandbox.owned_bytes(test, "after"))
                or r["before"]["status"] != "fail"
                or r["after"]["observations"] != owned.EXPECTED[test]
            ):
                raise ValueError("Owned repair integrity check failed")
        else:
            checked = dict(
                before=r["before"],
                after=r["after"],
                repair=r,
                snapshot={"files": {CONTROL: SAFE_HASH, SEARCH: r["original_sha256"]}},
            )
            if (
                r["verdict"] != "verified"
                or verdict(checked)[0] != "verified"
                or r["path"] != SEARCH
            ):
                raise ValueError("No verified parameter-binding repair")
        repo = Path(scan["snapshot"]["repository"])
        marker = repo.stat()
        if scan["snapshot"].get("directory_id", [marker.st_dev, marker.st_ino]) != [
            marker.st_dev,
            marker.st_ino,
        ]:
            raise ValueError("Repository directory identity changed")
        revision = git(repo, "rev-parse", "--verify", "HEAD", check=False).decode().strip() or None
        if not undo and revision != scan["snapshot"]["revision"]:
            raise ValueError("Stale apply: repository revision changed")
        path = plain(repo / r["path"])
        if scan["snapshot"]["files"].get(r["path"]) != r["original_sha256"]:
            raise ValueError("Receipt and snapshot disagree")
        current = path.read_bytes()
        candidate = r["candidate"].encode()
        if undo and r["state"] != "applied":
            raise ValueError("No applied repair to undo")
        expected = r["candidate_sha256"] if undo else r["original_sha256"]
        destination = r["original_sha256"] if undo else r["candidate_sha256"]
        key = sid if primary.get("finding_id") == fid else sid + "." + fid
        backup = history.home() / (key + ".original")
        journal = history.home() / (key + ".operation")
        operation = json_bytes(
            dict(scan=sid, state=r["state"], expected=expected, destination=destination)
        )
        resumed = (
            digest(current) == destination
            and journal.exists()
            and plain(journal).read_bytes() == operation
        )
        if not resumed and digest(current) != expected:
            raise ValueError("Stale undo" if undo else "Stale apply")
        if test:
            original = sandbox.owned_bytes(test, "before")
            if (
                candidate != sandbox.owned_bytes(test, "after")
                or owned.patch_text(r["path"], original, candidate) != r["diff"]
            ):
                raise ValueError("Owned fixture candidate changed")
            # The immutable synthetic fixture is the rollback source for sensitive configuration.
            backup_ref = "owned-v1/" + test if test == "configuration" else str(backup)
            if test != "configuration":
                if backup.exists() and plain(backup).read_bytes() != original:
                    raise ValueError("Backup hash mismatch")
                atomic_write(backup, original)
        else:
            backup_ref = str(backup)
            original = plain(backup).read_bytes() if undo or resumed else current
            change_diff = diff(original, candidate)
            if (
                not trusted(original)
                or not trusted(candidate)
                or digest(original) != r["original_sha256"]
                or digest(candidate) != r["candidate_sha256"]
                or digest(change_diff) != r["patch_sha256"]
                or change_diff.decode() != r["diff"]
                or not any(
                    fix(original, r["line"], {"path": SEARCH, "replacement": v.decode()})
                    == candidate
                    for v in (REPLACEMENT, REPLACEMENT.replace(b'"', b"'"))
                )
            ):
                raise ValueError("Repair integrity check failed")
            if backup.exists():
                if plain(backup).read_bytes() != original:
                    raise ValueError("Backup hash mismatch")
            else:
                atomic_write(backup, original)
        atomic_write(journal, operation)
        if plain(path).read_bytes() != current:
            raise ValueError("Concurrent edit")
        replacement = original if undo else candidate
        if not resumed:
            atomic_write(path, replacement, stat.S_IMODE(path.stat().st_mode))
        r.update(
            state="restored" if undo else "applied",
            application_actor="developer",
            backup_reference=backup_ref,
            undo_command="laundromat undo " + sid + (" --finding " + fid if fid else ""),
        )
        r["restored_sha256" if undo else "applied_sha256"] = digest(path.read_bytes())
        if primary.get("finding_id") == fid:
            db.execute("UPDATE repairs SET data=? WHERE scan=?", (history.encoded(r), sid))
        if fid:
            db.execute(
                "UPDATE finding_repairs SET data=? WHERE scan=? AND finding=?",
                (history.encoded(r), sid, fid),
            )
        for h in scan["findings"]:
            if h["path"] == r["path"] and h.get("state") == "property-confirmed":
                history.transition(
                    db, sid, h["id"], "restored" if undo else "fixed", r["property"], "developer"
                )
        history.event(db, sid, r["state"])
        return {"scan": sid, "state": r["state"], "sha256": digest(replacement), "path": str(path)}
