import difflib
import json
import os
import shutil
import stat
import time
import uuid
from pathlib import Path

from .checks import RULE_ID, check
from .snapshot import TOKEN
from .workspace import (
    CHECKOUT,
    EDITABLE,
    CONTROL,
    RUNS,
    SEARCH,
    SOURCES,
    WORK,
    Refused,
    atomic_write,
    digest,
    directory,
    json_bytes,
    plain,
    require_lab,
)

ORIGINAL = b"db.prepare(`SELECT id FROM swatches WHERE color = '${term}' ORDER BY id`).all()"
REPLACEMENT = b'db.prepare("SELECT id FROM swatches WHERE color = ? ORDER BY id").all(term)'


def template(data, line):
    lines = data.splitlines(keepends=True)
    if not 1 <= line <= len(lines) or lines[line - 1].count(ORIGINAL) != 1:
        raise Refused("The finding does not match the Phase 1 repair template.")
    lines[line - 1] = lines[line - 1].replace(ORIGINAL, REPLACEMENT)
    return b"".join(lines)


def diff(before, after, path=SEARCH):
    lines = difflib.diff_bytes(
        difflib.unified_diff,
        before.splitlines(True),
        after.splitlines(True),
        fromfile=("a/" + path).encode(),
        tofile=("b/" + path).encode(),
    )
    return b"".join(
        line if line.endswith(b"\n") else line + b"\n\\ No newline at end of file\n"
        for line in lines
    )


def supported_finding(phase):
    hits = phase["semgrep"].get("findings", [])
    if len(hits) == 1 and hits[0]["file"] == SEARCH and hits[0]["rule_id"] == RULE_ID:
        return hits[0]
    return None


def verdict(receipt):
    before, after = receipt["before"], receipt["after"]
    problems = [
        f"{stage} {name}: {result['reason']}"
        for stage, phase in (("before", before), ("after", after))
        if phase is not None
        for name, result in phase.items()
        if result["status"] == "incomplete"
    ]
    if problems:
        return "incomplete", " | ".join(problems)
    if not supported_finding(before):
        return "unverified", "Expected exactly one supported finding and a clean control."
    if not after:
        return "unverified", "No supported candidate was checked."

    def measured_binding(phase):
        rows = phase["binding"].get("observations", [])
        if [r["term"] for r in rows] != ["amber", "indigo"] or any(
            len(r["statements"]) != 1 for r in rows
        ):
            return None
        return len({r["statements"][0]["sql"] for r in rows}) == 1 and all(
            r["statements"][0]["executions"] == [[r["term"]]] for r in rows
        )

    verified = (
        measured_binding(before) is False
        and measured_binding(after) is True
        and after["semgrep"]["scanned"].get(CONTROL) == receipt["snapshot"]["files"][CONTROL]
        and before["binding"]["status"] == "fail"
        and after["binding"]["status"] == "pass"
        and after["semgrep"]["findings"] == []
        and all(p["semgrep"]["negative_control"] == "pass" for p in (before, after))
        and all(p["sqlite"]["status"] == "pass" for p in (before, after))
        and all(
            {row["term"]: row["actual"] for row in p["sqlite"].get("results", [])}
            == {"amber": [101, 109], "indigo": [104], "jade": []}
            for p in (before, after)
        )
        and before["semgrep"]["scanned"] == receipt["snapshot"]["files"]
        and after["semgrep"]["scanned"][SEARCH] == receipt["repair"]["candidate_sha256"]
    )
    if verified:
        return "verified", None
    return "unverified", "One or more verification conditions failed. See individual checks."


def review():
    start = time.perf_counter()
    require_lab()
    run = directory(RUNS) / uuid.uuid4().hex
    baseline = run / "before"
    baseline.mkdir(parents=True)
    for name in SOURCES:
        content = plain(WORK / name).read_bytes()
        if TOKEN.search(content.decode(errors="replace")):
            raise Refused(
                "Synthetic credential in input. Use laundromat scan for a redacted snapshot."
            )
        (baseline / name).write_bytes(content)
    files = {name: digest((baseline / name).read_bytes()) for name in SOURCES}
    before = check(baseline, "local")
    finding = supported_finding(before)
    receipt = {
        "schema_version": 1,
        "receipt": str(run / "receipt.json"),
        "snapshot": {"sha256": digest(json_bytes(files)), "files": files},
        "finding": finding,
        "repair": None,
        "before": before,
        "after": None,
    }
    reason = None
    if finding:
        original = (baseline / SEARCH).read_bytes()
        try:
            repaired = template(original, finding["line"])
        except Refused as exc:
            reason = str(exc)
        else:
            candidate = run / "candidate"
            shutil.copytree(baseline, candidate)
            (candidate / SEARCH).write_bytes(repaired)
            patch = diff(original, repaired)
            (run / "repair.diff").write_bytes(patch)
            receipt["repair"] = {
                "source": "template",
                "file": SEARCH,
                "patch": "repair.diff",
                "patch_sha256": digest(patch),
                "candidate_sha256": digest(repaired),
            }
            receipt["after"] = check(candidate, "local")
    receipt["verdict"], outcome_reason = verdict(receipt)
    receipt["reason"] = reason or outcome_reason
    receipt["runtime_attempts"] = {}
    for name, phase in (("before", before), ("after", receipt["after"])):
        if phase:
            receipt["runtime_attempts"][name] = {
                k: phase[k].pop("attempt") for k in ("binding", "sqlite") if "attempt" in phase[k]
            }
    receipt["elapsed_ms"] = round((time.perf_counter() - start) * 1000)
    atomic_write(run / "receipt.json", json_bytes(receipt))
    return receipt


def change(receipt_path: Path, *, undo: bool):
    path = resolve_receipt(receipt_path)
    runs, work = receipt_workspace(path)
    run = path.parent
    if run.parent != runs or path.name != "receipt.json":
        raise Refused("Use a receipt from this workspace's runs directory.")
    receipt = json.loads(path.read_bytes())
    if (
        receipt["schema_version"] != 1
        or receipt["verdict"] != "verified"
        or verdict(receipt)[0] != "verified"
    ):
        raise Refused("This receipt does not contain a verified repair.")

    finding = supported_finding(receipt["before"])
    scanned = finding["scanned_sha256"]
    applied = receipt["repair"]["candidate_sha256"]
    target = plain(work / SEARCH)
    current = target.read_bytes()
    expected = applied if undo else scanned
    if digest(current) != expected:
        raise Refused(
            f"Stale {'undo' if undo else 'apply'}: {SEARCH} no longer matches {expected}."
        )

    backup = run / "original.bin"
    if undo:
        replacement = plain(backup).read_bytes()
        if digest(replacement) != scanned:
            raise Refused("The saved original does not match the scanned hash.")
    else:
        replacement = plain(run / "candidate" / SEARCH).read_bytes()
        patch = plain(run / "repair.diff").read_bytes()
        if (
            digest(replacement) != applied
            or replacement != template(current, finding["line"])
            or patch != diff(current, replacement)
            or digest(patch) != receipt["repair"]["patch_sha256"]
        ):
            raise Refused("The candidate or diff does not match the reviewed repair.")
        if backup.exists() or backup.is_symlink():
            if plain(backup).read_bytes() != current:
                raise Refused("The existing backup differs from the scanned file.")
        else:
            atomic_write(backup, current)
    mode = stat.S_IMODE(target.stat().st_mode)
    if plain(target).read_bytes() != current:
        raise Refused(f"{SEARCH} changed during review. Retry with a fresh receipt.")
    atomic_write(target, replacement, mode)


def receipt_workspace(path):
    roots = [RUNS.parent]
    if EDITABLE:
        roots.append(CHECKOUT / ".laundromat")
    for lab in roots:
        if (
            path.parent.parent == lab / "runs"
            and plain(lab / ".phase1-workspace").read_bytes() == b"laundromat phase 1\n"
        ):
            return lab / "runs", lab / "workspace"
    raise Refused("Use a receipt from a marked workspace.")


def resolve_receipt(value):
    path = Path(value)
    if EDITABLE and not path.exists() and path.parts[:2] == (".laundromat", "runs"):
        path = CHECKOUT / path
    return plain(Path(os.path.abspath(path)))
