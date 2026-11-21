"""Read-only application-code review of outgoing Git changes and local snapshots."""

import difflib
import json
import os
import posixpath
import re
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from . import manifests, provider
from .snapshot import IGNORE, git

SOURCE = manifests.SOURCE | {
    ".cs", ".go", ".java", ".kt", ".php", ".py", ".rb", ".rs", ".sql", ".vue",
}
MAX_FILES = 16
MAX_BYTES = 32_768
MAX_LINES = 800
EXCERPT_LINES = 20
PAYLOAD_CHARS = 5_400
DIFF_CHARS = 4_500
HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    anchor: str
    title: str = Field(min_length=1, max_length=100)
    explanation: str = Field(min_length=1, max_length=450)
    recommendation: str = Field(min_length=1, max_length=350)


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    findings: list[Advisory] = Field(max_length=5)


def revisions(repo, updates, commits):
    outgoing = set(commits)
    pairs = set()
    for update in updates:
        if not update["tip"].strip("0"):
            continue
        tip = git(repo, "rev-parse", "--verify", update["tip"] + "^{commit}").decode().strip()
        if update["base"].strip("0"):
            base = git(repo, "rev-parse", "--verify", update["base"] + "^{commit}").decode().strip()
        elif tip in outgoing:
            parents = git(repo, "rev-list", "--first-parent", "--max-count=257", tip).decode().splitlines()
            base = next((commit for commit in parents if commit not in outgoing), None)
            if base is None:
                base = git(repo, "hash-object", "-t", "tree", "--", os.devnull).decode().strip()
        else:
            continue
        if base != tip:
            pairs.add((base, tip))
    return sorted(pairs)


def source_path(path):
    name = PurePosixPath(path)
    return (
        path.isprintable()
        and provider.redact(path) == path
        and name.suffix in SOURCE
        and not set(name.parts) & (IGNORE | manifests.EXCLUDED)
    )


def changed_files(repo, base, tip):
    entries = git(
        repo, "diff", "--raw", "--no-abbrev", "-z", "--no-renames",
        "--no-ext-diff", "--no-textconv", base, tip, "--",
    ).split(b"\0")
    for meta, name in zip(entries[0:-1:2], entries[1::2], strict=True):
        path = os.fsdecode(name)
        if not source_path(path):
            continue
        old_mode, new_mode, old_oid, new_oid, _ = meta[1:].decode().split()
        if {old_mode, new_mode} <= {"000000", "100644", "100755"} and old_oid != new_oid:
            yield path, old_oid, new_oid


def read_source(repo, oid):
    if not oid.strip("0"):
        return ""
    if int(git(repo, "cat-file", "-s", oid)) > MAX_BYTES:
        return None
    return decode_source(git(repo, "cat-file", "blob", oid))


def decode_source(data):
    if len(data) > MAX_BYTES or b"\0" in data or data.count(b"\n") >= MAX_LINES:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def source_lines(text):
    lines = text.split("\n")
    return [line + "\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def diff_hunks(before, after):
    hunk = []
    for row in difflib.unified_diff(source_lines(before), source_lines(after), n=6, lineterm=""):
        row = row.removesuffix("\n")
        if row.startswith("@@ "):
            if hunk:
                yield hunk
            hunk = [row]
        elif hunk:
            hunk.append(row)
    if hunk:
        yield hunk


def anchored_hunk(hunk, first_anchor):
    old, _, new, _ = (int(value or 1) for value in HUNK.fullmatch(hunk[0]).groups())
    rows, anchors = [hunk[0]], {}
    for row in hunk[1:]:
        mark = row[0]
        if mark in ("+", "-"):
            anchor = f"A{first_anchor + len(anchors)}"
            anchors[anchor] = ("after", new) if mark == "+" else ("before", old)
            row = f"{mark} [{anchor}] {row[1:]}"
        rows.append(row)
        old += mark != "+"
        new += mark != "-"
    return provider.redact("\n".join(rows)), anchors


def import_context(repo, tip, path, source, secret_paths):
    if PurePosixPath(path).suffix not in manifests.SOURCE or not source:
        return
    imports, _ = manifests.literals(path, source.encode())
    extensions = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
    for spec in sorted(ref for ref in imports if ref.startswith(("./", "../")))[:4]:
        stem = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
        if stem == ".." or stem.startswith("../"):
            continue
        candidates = [stem, *(stem + ext for ext in extensions)]
        candidates.extend(stem + "/index" + ext for ext in extensions)
        names = [name for name in candidates if source_path(name) and name not in secret_paths]
        if not names:
            continue
        entries = git(repo, "--literal-pathspecs", "ls-tree", "-z", tip, "--", *names)
        matches = {}
        for entry in entries.split(b"\0"):
            if entry:
                meta, _, name = entry.partition(b"\t")
                mode, _, oid = meta.decode().split()
                if mode in ("100644", "100755"):
                    matches[os.fsdecode(name)] = oid
        name = stem if stem in matches else next(iter(matches)) if len(matches) == 1 else None
        if name is not None and (data := read_source(repo, matches[name])):
            yield dict(
                path=name, start_line=1,
                source=provider.redact("\n".join(data.splitlines()[:18])),
            )


def artifact_for(repo, updates, commits, secret_paths, receipt):
    artifact = {"changes": [], "related_code": []}
    locations, context_sources = {}, []
    examined = 0
    for base, tip in revisions(repo, updates, commits):
        for path, old, new in changed_files(repo, base, tip):
            if path in secret_paths or examined >= MAX_FILES:
                receipt["omitted_files"] += 1
                continue
            examined += 1
            before, after = read_source(repo, old), read_source(repo, new)
            if before is None or after is None:
                receipt["omitted_files"] += 1
                continue
            first_change = add_hunks(
                artifact, locations, base, tip, path, diff_hunks(before, after), receipt
            )
            if first_change is not None:
                context_sources.append((tip, path, after, first_change))
    seen = {(tip, path) for tip, path, _, _ in context_sources}
    for tip, path, data, change in context_sources:
        for excerpt in import_context(repo, tip, path, data, secret_paths):
            key = (tip, excerpt["path"])
            if key in seen:
                continue
            seen.add(key)
            artifact["related_code"].append(dict(excerpt, related_to_change=change))
            if len(json.dumps(artifact)) > PAYLOAD_CHARS:
                artifact["related_code"].pop()
            if len(artifact["related_code"]) >= 2:
                return artifact, locations
    return artifact, locations


def add_hunks(artifact, locations, base, tip, path, hunks, receipt):
    changes = artifact["changes"]
    first_change = len(changes) + 1
    omitted = False
    for hunk in hunks:
        diff, anchors = anchored_hunk(hunk, len(locations) + 1)
        changes.append(dict(change=len(changes) + 1, path=path, diff=diff))
        if len(json.dumps(artifact)) > DIFF_CHARS:
            changes.pop()
            omitted = True
            continue
        locations.update({
            anchor: (base, tip, path, side, line)
            for anchor, (side, line) in anchors.items()
        })
    receipt["omitted_files"] += omitted
    if first_change <= len(changes):
        receipt["reviewed_files"] += 1
        return first_change
    return None


def snapshot_hunks(source):
    lines = source_lines(source)
    for start in range(0, len(lines), EXCERPT_LINES):
        rows = lines[start:start + EXCERPT_LINES]
        yield [
            f"@@ -0,0 +{start + 1},{len(rows)} @@",
            *("+" + line.removesuffix("\n") for line in rows),
        ]


def snapshot_artifact(snapshot, files, checked_paths, secret_paths, receipt):
    artifact = {"scope": "snapshot", "changes": [], "related_code": []}
    locations = {}
    examined = 0
    for path, data in sorted(files.items()):
        if not data or not source_path(path):
            continue
        if path in secret_paths or path not in checked_paths or examined >= MAX_FILES:
            receipt["omitted_files"] += 1
            continue
        examined += 1
        source = decode_source(data)
        if source is None:
            receipt["omitted_files"] += 1
            continue
        add_hunks(artifact, locations, None, snapshot["sha256"], path, snapshot_hunks(source), receipt)
    return artifact, locations


def validate(answer, locations):
    findings, seen = [], set()
    for finding in Review.model_validate(answer).findings:
        base, tip, path, side, line = locations[finding.anchor]
        key = (tip, path, side, line, finding.title)
        if key in seen:
            continue
        seen.add(key)
        fields = {
            name: " ".join(provider.redact(getattr(finding, name)).split())
            for name in ("title", "explanation", "recommendation")
        }
        if not all(value and value.isprintable() for value in fields.values()):
            raise ValueError("Finding text is empty or contains control characters")
        findings.append(dict(
            **fields, path=path, commit=tip if base is not None else None,
            revision=base if side == "before" else tip,
            side=side, line=line, end_line=line,
        ))
    return findings


def inspect(repo, updates, commits, scan, report):
    if not any(update["tip"].strip("0") for update in updates):
        return skipped("No outgoing ref changes")
    if scan["coverage"]["history_process"] == "incomplete":
        return skipped("Outgoing credential scan incomplete")
    return review(
        scan,
        lambda secrets, receipt: artifact_for(repo, updates, commits, secrets, receipt),
        lambda: report("llm-review"),
        "No source diff fit the review scope",
        "No changed source in scope",
    )


def inspect_snapshot(snapshot, files, scan, phase_callback):
    coverage = scan["coverage"]["secret"]
    checked = set(coverage["paths"]) - set(coverage.get("failed_paths", ()))
    if coverage["status"] == "incomplete" and not checked:
        return skipped("Local credential scan incomplete")
    return review(
        scan,
        lambda secrets, receipt: snapshot_artifact(snapshot, files, checked, secrets, receipt),
        lambda: phase_callback("Reviewing source with the model…") if phase_callback else None,
        "No source excerpts fit the review scope",
        "No source in scope",
    )


def skipped(reason):
    return dict(status="skipped", findings=[], reviewed_files=0, omitted_files=0, reason=reason)


def review(scan, prepare, announce, omitted_reason, empty_reason):
    try:
        provider.configuration()
    except ValueError:
        return skipped("Model provider is not configured")

    receipt = dict(status="skipped", findings=[], reviewed_files=0, omitted_files=0)
    trace = []
    failure = "Could not prepare advisory review"
    try:
        secrets = {hit["path"] for hit in scan["findings"] if hit["category"] == "secret"}
        artifact, locations = prepare(secrets, receipt)
        if not locations:
            reason = omitted_reason if receipt["omitted_files"] else empty_reason
            return dict(receipt, reason=reason)
        announce()
        schema = Review.model_json_schema()
        schema["$defs"][Advisory.__name__]["properties"]["anchor"]["enum"] = list(locations)
        failure = "Model provider call failed"
        answer = provider.role("Review", artifact, trace, timeout=12, response_schema=schema)
        failure = "Model returned invalid advisory findings"
        receipt["findings"] = validate(answer, locations)
    except Exception:
        # Advisory failures must never interrupt the local checks or push workflow.
        if trace and trace[-1].get("output_limit_reached"):
            failure = "Model response reached the advisory output limit"
        receipt.update(status="unavailable", reason=failure)
    else:
        receipt["status"] = "partial" if receipt["omitted_files"] else "complete"
    if trace:
        receipt["model_call"] = {
            key: trace[0][key] for key in
            ("origin", "model", "prompt_version", "input_digest", "duration_ms")
            if key in trace[0]
        }
    return receipt
