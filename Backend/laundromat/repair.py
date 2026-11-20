"""Fix proposes bytes. Verify runs trusted checks. Only the controller authorizes changes."""

import ast
import json
import re
import stat
import tempfile
import time
from pathlib import Path

from . import history, provider
from .manifests import SOURCE, parse_source
from .checks import check
from .sandbox import report_verified_patch, suite_digest
from .review import REPLACEMENT, diff, template, verdict
from .snapshot import HEADER, ORIGINAL_HASH, SAFE_HASH, TOKEN, git, relative, trusted
from .workspace import FIXTURE, SEARCH, CONTROL, atomic_write, digest, plain, json_bytes


SECRET_SUITE = "secret-env-substitution-v1"
SECRET_RULES = {
    "github-pat": ("ghp_", "GITHUB_TOKEN"),
    "github-fine-grained": ("github_pat_", "GITHUB_TOKEN"),
    "api-key": ("sk-proj-", "OPENAI_API_KEY"),
    "aws-access-id": ("AKIA", "AWS_ACCESS_KEY_ID"),
    "laundromat-synthetic-credential": ("LMTEST_", "API_SECRET"),
}
QUOTED_TOKEN = re.compile(rb"""(["'`])(""" + TOKEN.pattern.encode() + rb""")\1""")


def python_env_import(module, lines, line):
    """Return an optional import insertion, preserving the Python file prologue."""
    for statement in module.body:
        if isinstance(statement, ast.Import) and statement.lineno < line and any(
            alias.name == "os" and not alias.asname for alias in statement.names
        ):
            return None
    for i, statement in enumerate(module.body):
        if i == 0 and ast.get_docstring(module) is not None:
            continue
        if isinstance(statement, ast.ImportFrom) and statement.module == "__future__":
            continue
        decorators = getattr(statement, "decorator_list", ())
        first = min([statement.lineno, *(d.lineno for d in decorators)])
        pos = sum(map(len, lines[:first - 1]))
        newline = b"\r\n" if any(row.endswith(b"\r\n") for row in lines[:first]) else b"\n"
        return pos, b"import os" + newline
    return None


def secret_candidate(data, finding):
    path, line = finding["path"], finding.get("line")
    lines = data.splitlines(keepends=True)
    if type(line) is not int or not 1 <= line <= len(lines):
        return None
    prefix, env_var = SECRET_RULES.get(finding["rule"], ("", "SECRET_VALUE"))
    column = finding.get("evidence", {}).get("column")
    suffix = Path(path).suffix.lower()
    source = None
    if suffix == ".py":
        source = ast.parse(data)
        strings = {
            (node.col_offset, node.end_col_offset)
            for node in ast.walk(source)
            if isinstance(node, ast.Constant) and node.lineno == node.end_lineno == line
        }
        # A module docstring must stay before imports and future directives.
        if ast.get_docstring(source) is not None and source.body[0].lineno == line:
            return None
    elif suffix in SOURCE:
        source = parse_source(path, data)
    offset = sum(map(len, lines[:line - 1]))
    for match in QUOTED_TOKEN.finditer(lines[line - 1]):
        if not match[2].startswith(prefix.encode()):
            continue
        # Gitleaks 8.28 includes the preceding newline in subsequent line columns.
        if column and column - match.start(2) not in (1, 2):
            continue
        start, end = offset + match.start(), offset + match.end()
        if suffix == ".py":
            if match.span() not in strings:
                continue
            replacement = f'os.environ["{env_var}"]'.encode()
            candidate = data[:start] + replacement + data[end:]
            if insertion := python_env_import(source, lines, line):
                pos, statement = insertion
                candidate = candidate[:pos] + statement + candidate[pos:]
            compile(candidate, path, "exec")
        else:
            if source is not None:
                literal = source.descendant_for_byte_range(start, end)
                if literal.type not in ("string", "template_string") or literal.byte_range != (start, end):
                    continue
            candidate = data[:start] + f"process.env.{env_var}".encode() + data[end:]
            if source is not None and parse_source(path, candidate).has_error:
                continue
        return candidate
    return None


def propose_secret_repair(data: bytes, finding: dict) -> dict | None:
    try:
        candidate = secret_candidate(data, finding)
        if candidate is None:
            return None
        display = provider.redact(candidate.decode())
        patch = provider.redact(diff(data, candidate, finding["path"]).decode())
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        return None
    return dict(
        property="no literal secret in source", suite=SECRET_SUITE, origin="template",
        path=finding["path"], line=finding["line"], state="candidate", verdict="candidate",
        reason="Replace the literal value with an environment variable reference. Rotate the original secret.",
        original_sha256=digest(data), candidate_sha256=digest(candidate), candidate=display,
        diff=patch, patch_sha256=digest(patch.encode()), before={"status": "finding present"},
        after={"status": "structural substitution applied"}, elapsed_ms=0, finding_id=finding["id"],
    )


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


def verify(original, candidate, origin, line, before=None, progress_callback=None):
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
        before = before or check(path, progress_callback=progress_callback)
        (path / SEARCH).write_bytes(candidate)
        if progress_callback:
            progress_callback(f"[sandbox] Checking repair candidate ({origin})...")
        after = check(path, progress_callback=progress_callback)
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


def propose(data, finding, use_model, *, fallback=True, model_context=None, progress_callback=None):
    if digest(data.removeprefix(HEADER)) != ORIGINAL_HASH or finding["path"] != SEARCH:
        finding["repair_status"] = "unsupported fixture or query style"
        return None
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / SEARCH).write_bytes(data)
        (root / CONTROL).write_bytes((FIXTURE / "fixture" / CONTROL).read_bytes())
        before = check(root, progress_callback=progress_callback)
    if progress_callback:
        binding = before["binding"]
        detail = " — SQL template varies with input" if binding.get("constant_sql") is False else ""
        progress_callback(f"[sandbox] BEFORE binding: {binding['status'].upper()}{detail}")
    finding["original_observations"] = before
    if (
        before["binding"]["status"] != "fail"
        or before["semgrep"].get("negative_control") != "pass"
        or before["sqlite"]["status"] != "pass"
    ):
        finding["repair_status"] = "original property check incomplete or negative"
        if progress_callback:
            progress_callback("[sandbox] AFTER  binding: candidate not tested")
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
    result = verify(data, candidate, origin, finding["line"], before, progress_callback)
    if progress_callback:
        binding_status = result["after"]["binding"]["status"]
        detail = " — parameterized query confirmed" if binding_status == "pass" else ""
        progress_callback(f"[sandbox] AFTER  binding: {binding_status.upper()}{detail}")
        if result["verdict"] == "verified":
            elapsed = round((time.monotonic() - started) * 1000)
            report_verified_patch(progress_callback, result["property"], elapsed)
        else:
            progress_callback(f"[sandbox] Patch verification: {result['verdict'].upper()}")
    result.update(model_issue=issue, model_explanation=explanation, usage=usage, model=model)
    finding["repair_status"] = result["verdict"] + " parameter binding"
    return result


def apply_candidate_repair(sid, finding_id):
    """Apply a reviewed structural repair and retain the original for undo."""
    if not finding_id:
        raise ValueError("Select the finding ID of the reviewed candidate")
    return change(sid, False, finding_id, candidate_only=True)


def change(sid, undo, finding_id=None, *, candidate_only=False):
    # Serialize operations against the same ledger, including writes from other CLI processes.
    scan = history.detail(sid)
    if scan.get("provenance") == "demo replay":
        raise ValueError("Historical demo replay is read-only")
    if scan.get("proposal_state"):
        from .proposal import decide

        if not undo:
            raise ValueError("Use laundromat accept for a reviewed agent proposal")
        return decide(sid, "undo")
    with history.database() as db:
        row = db.execute("SELECT data FROM repairs WHERE scan=?", (sid,)).fetchone()
        primary = json.loads(row[0]) if row else {}
        if finding_id:
            row = db.execute(
                "SELECT data FROM finding_repairs WHERE scan=? AND finding=?", (sid, finding_id)
            ).fetchone()
        if not row:
            raise ValueError("No repair found for this finding or scan")
        r = json.loads(row[0])
        if r.get("imported"):
            raise ValueError("Use the originating receipt for an imported repair")
        fid = r.get("finding_id")
        secret = r.get("suite") == SECRET_SUITE and r.get("verdict") == "candidate"
        if candidate_only and not secret:
            raise ValueError("Use laundromat apply for verified repairs")
        if secret:
            if not undo and not candidate_only:
                raise ValueError("Review the diff and use laundromat apply-candidate SCAN_ID FINDING_ID")
            finding = next((f for f in scan["findings"] if f["id"] == fid and f["category"] == "secret"), None)
            if (
                not finding or (finding_id and fid != finding_id)
                or finding["path"] != r["path"] or finding["line"] != r["line"]
                or scan.get("trigger") == "pre-push"
            ):
                raise ValueError("Secret repair does not match this finding")
        elif scan["status"] == "incomplete" or (
            "verified_actions" in scan and not scan["verified_actions"]
        ):
            raise ValueError("No applicable verified repair")
        elif fid and not any(a.get("finding_id") == fid for a in scan.get("verified_actions", [])):
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
        elif not secret:
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
        path = plain(repo / relative(r["path"]))
        if scan["snapshot"]["files"].get(r["path"]) != r["original_sha256"]:
            raise ValueError("Receipt and snapshot disagree")
        current = path.read_bytes()
        candidate = r["candidate"].encode()
        if undo and r["state"] != "applied":
            raise ValueError("No applied repair to undo")
        expected = r["candidate_sha256"] if undo else r["original_sha256"]
        destination = r["original_sha256"] if undo else r["candidate_sha256"]
        key = sid if primary.get("finding_id") == fid and not secret else sid + "." + fid
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
            if secret:
                # Regenerate from the hash-checked preimage. Display evidence is
                # redacted and may contain other credential placeholders.
                candidate = secret_candidate(original, finding)
                if candidate is None or provider.redact(candidate.decode()) != r["candidate"]:
                    raise ValueError("Secret repair integrity check failed")
                change_diff = provider.redact(diff(original, candidate, r["path"]).decode()).encode()
            elif (
                not trusted(original)
                or not trusted(candidate)
                or not any(
                    fix(original, r["line"], {"path": SEARCH, "replacement": v.decode()})
                    == candidate
                    for v in (REPLACEMENT, REPLACEMENT.replace(b'"', b"'"))
                )
            ):
                raise ValueError("Repair integrity check failed")
            else:
                change_diff = diff(original, candidate)
            if (
                digest(original) != r["original_sha256"]
                or digest(candidate) != r["candidate_sha256"]
                or digest(change_diff) != r["patch_sha256"]
                or change_diff.decode() != r["diff"]
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
            affected = h["id"] == fid if secret else (
                h["path"] == r["path"] and h.get("state") == "property-confirmed"
            )
            if affected:
                history.transition(
                    db, sid, h["id"], "restored" if undo else "fixed", r["property"], "developer"
                )
        history.event(db, sid, "applied candidate" if secret and not undo else r["state"])
        result = {"scan": sid, "state": r["state"], "sha256": digest(replacement), "path": str(path)}
        if secret:
            result["backup"] = backup_ref
        return result
