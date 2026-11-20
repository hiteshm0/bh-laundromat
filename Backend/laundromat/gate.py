"""Local pre-push policy over immutable Git objects. No checkout or model is invoked."""

import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import detect, history, pipeline
from .snapshot import LIMIT, TOKEN, git
from .workspace import digest, json_bytes

OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def install(repo):
    repo = Path(repo).resolve()
    if git(repo, "config", "--get", "core.hooksPath", check=False).strip():
        raise ValueError(
            'Existing core.hooksPath configuration preserved. Integrate laundromat gate --repo . --remote "$2" with its stdin.'
        )
    directory = Path(
        os.fsdecode(git(repo, "rev-parse", "--path-format=absolute", "--git-path", "hooks").strip())
    )
    if directory != directory.resolve():
        raise ValueError("Custom symlinked hooks directory preserved")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "pre-push"
    cli = Path(sys.executable).parent / "laundromat"
    script = (
        '#!/bin/sh\nexport PATH="$PATH":'
        + shlex.quote(str(cli.parent))
        + "\n"
        + shlex.quote(str(cli))
        + ' gate --repo . --remote "$2" || exit 1\n'
    )
    if path.is_symlink() or (path.exists() and path.read_text() != script):
        raise ValueError(
            'Existing pre-push hook preserved. Integrate laundromat gate --repo . --remote "$2" with its stdin.'
        )
    if not path.exists():
        with path.open("x") as stream:
            stream.write(script)
    path.chmod(0o755)
    return {"hook": str(path)}


def commits_for(repo, remote, lines):
    tips, bases, updates = [], set(), []
    for line in lines.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 4 or not all(OID.fullmatch(x) for x in (parts[1], parts[3])):
            raise ValueError("Malformed pre-push update")
        local, tip, ref, base = parts
        updates.append({"local": local, "tip": tip, "remote": ref, "base": base})
        if not tip.strip("0"):
            continue
        tips.append(git(repo, "rev-parse", "--verify", tip + "^{commit}").decode().strip())
        if base.strip("0"):
            resolved = (
                git(repo, "rev-parse", "--verify", base + "^{commit}", check=False).decode().strip()
            )
            if not OID.fullmatch(resolved):
                raise ValueError(f"Remote base object {base} is unavailable locally")
            bases.add(resolved)
    if not tips:
        return updates, [], []
    if git(repo, "rev-parse", "--is-shallow-repository").strip() == b"true":
        raise ValueError("Shallow clone cannot establish complete outgoing history")
    # A local rehearsal remote can supply its exact advertised refs without network access.
    local_remote = (repo / remote).resolve()
    if remote and local_remote.is_dir():
        for oid in (
            git(local_remote, "for-each-ref", "--format=%(objectname)").decode().splitlines()
        ):
            commit = (
                git(repo, "rev-parse", "--verify", oid + "^{commit}", check=False).decode().strip()
            )
            if OID.fullmatch(commit):
                bases.add(commit)
    args = ["rev-list", "--topo-order", "--reverse", *tips]
    if bases:
        args.extend(["--not", *sorted(bases)])
    commits = git(repo, *args[:1], "--max-count=257", *args[1:]).decode().splitlines()
    if len(commits) > 256 or len(updates) > 64:
        raise ValueError("Outgoing history exceeds 256 commits or 64 ref updates")
    return updates, commits, sorted(set(tips))


def tree(repo, commit):
    entries = git(repo, "ls-tree", "-r", "-z", commit).split(b"\0")
    if len(entries) > 4097:
        raise ValueError("Commit tree exceeds the 4096-path limit")
    for entry in entries:
        if entry:
            meta, name = entry.split(b"\t", 1)
            mode, kind, oid = meta.decode().split()
            if kind != "blob":
                raise ValueError("Submodule history is outside the required scan")
            name = os.fsdecode(name)
            if TOKEN.search(name) or any(ord(c) < 32 for c in name):
                raise ValueError("Sensitive or unsupported Git path")
            yield name, oid


def decide(repo, remote, lines):
    repo = Path(repo).resolve()
    start = time.monotonic()
    updates, commits, tips, hits, issues = [], [], [], [], []
    blobs, secret_cache, metadata = {}, {}, []
    structure, tip_coverage = [], []
    sid = history.submit(
        dict(
            trigger="pre-push",
            pid=os.getpid(),
            scope=None,
            snapshot=dict(repository=str(repo), sha256=None, revision=None, files={}, issues=[]),
        ),
        uuid.uuid4().hex,
        state="deciding",
    )
    history_status, tip_status = "incomplete", "outside scope"
    versions = {"secret_rules_sha256": digest((detect.RULES / "synthetic.toml").read_bytes())}
    try:
        updates, commits, tips = commits_for(repo, remote, lines)
        total_bytes = 0

        def read(oid):
            nonlocal total_bytes
            if oid not in blobs:
                size = int(git(repo, "cat-file", "-s", oid))
                total_bytes += size
                if len(blobs) >= 4096 or total_bytes > 32_000_000 or size > LIMIT:
                    raise ValueError("Outgoing blob exceeds 2 MB history scan limit")
                blobs[oid] = git(repo, "cat-file", "blob", oid)
            return blobs[oid]

        try:
            if commits:
                p = subprocess.run(
                    ["gitleaks", "version"], capture_output=True, timeout=5, check=True
                )
                versions["gitleaks"] = p.stdout.decode().strip()

            for commit in commits:
                message = git(repo, "cat-file", "commit", commit).partition(b"\n\n")[2]
                hits.extend(detect.secrets(message, "(commit message)", commit))
                for name, oid in tree(repo, commit):
                    data = read(oid)
                    if b"\0" in data:
                        raise ValueError("Binary blob outside required text history coverage")
                    if oid not in secret_cache:
                        secret_cache[oid] = detect.secrets(data, "blob")
                    for match in secret_cache[oid]:
                        hits.append(
                            detect.finding(
                                "secret",
                                match["rule"],
                                name,
                                match["line"],
                                match["severity"],
                                "Gitleaks",
                                match["explanation"],
                                commit=commit,
                            )
                        )
            history_status = "complete" if commits else "no outgoing commits"
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            issues.append("Required scan incomplete: outgoing history: " + str(exc))
        tip_issue_count = len(issues)
        tip_status = "incomplete" if tips else "no outgoing tips"
        for tip in tips:
            files = {name: read(oid) for name, oid in tree(repo, tip)}
            bases = {u["base"] for u in updates if u["tip"] == tip} or {"0" * 40}
            for base in sorted(bases):
                prior = (
                    {
                        n: git(repo, "show", base + ":" + n, check=False) or b"{}"
                        for n in files
                        if n.endswith("package.json")
                    }
                    if base.strip("0")
                    else {}
                )
                req = {
                    "snapshot": {"issues": []},
                    "baseline_known": True,
                    "skip_history_secrets": True,
                }
                checked = pipeline.inspect(req, files, before_files=prior, verify=False)
                issues.extend(checked["issues"])
                tip_coverage.append(
                    dict(
                        commit=tip,
                        base=base,
                        coverage=checked["coverage"],
                        reason="New branch compared against empty declarations; reachable history scanned conservatively"
                        if not base.strip("0")
                        else "Compared supplied remote base",
                    )
                )
                for hit in checked["findings"]:
                    hit["evidence"]["commit"] = tip
                    hits.append(hit)
                for signal in checked["dependency_changes"]:
                    if signal["gained"]:
                        hits.append(
                            detect.finding(
                                "metadata",
                                "install-script-change",
                                "recorded-package.json",
                                None,
                                "P4",
                                "recorded metadata",
                                "Recorded version gains an install-time script.",
                                record=signal,
                                commit=tip,
                            )
                        )
                metadata.extend(checked["dependency_changes"])
                structure.extend(checked["structural_observations"])
        if tips and len(issues) == tip_issue_count:
            tip_status = "complete"
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        issues.append("Required scan incomplete: " + str(exc))
    scope_hash = digest(json_bytes({"updates": updates, "commits": commits, "tips": tips}))
    with history.database() as db:
        acknowledged = {
            r[0]
            for r in db.execute(
                "SELECT finding FROM acknowledgements WHERE repo=? AND snapshot=?",
                (str(repo), scope_hash),
            )
        }
    hits.sort(key=lambda h: (h["severity"], h["path"], h["line"] or 0))
    for h in hits:
        h["scope_limits"] = pipeline.LIMITS
    pending = sorted({h["id"] for h in hits if h["push_policy"] == "acknowledge"} - acknowledged)
    if issues:
        action, reason = "block", "; ".join(issues)
    elif any(h["push_policy"] == "block" for h in hits):
        action, reason = "block", "Credential match in outgoing history; owner remediation required"
    elif pending:
        action, reason = (
            "acknowledge",
            "P2 warning requires acknowledgement for this finding and snapshot",
        )
    else:
        action, reason = "allow", "Local policy checks satisfied"
    req = dict(
        trigger="pre-push",
        snapshot=dict(
            repository=str(repo), sha256=scope_hash, revision=tips, files={}, issues=issues
        ),
        scope=commits,
        updates=updates,
    )
    with history.database() as db:
        db.execute("UPDATE scans SET request=? WHERE id=?", (history.encoded(req), sid))
    result = dict(
        status="incomplete" if issues else "findings" if hits else "clean",
        findings=hits,
        issues=issues,
        push_decision=dict(action=action, reason=reason, pending=pending),
        versions=versions,
        coverage=dict(
            outgoing_commits=len(commits),
            history_blobs=len(secret_cache),
            tips=tips,
            history_process=history_status,
            tip_checks=tip_status,
        ),
        raw_candidates=[
            {k: h[k] for k in ("id", "category", "rule", "path", "line", "severity")} for h in hits
        ],
        verified_actions=[],
        unsupported_checks=issues,
        dependency_changes=metadata,
        structural_observations=structure,
        tip_coverage=tip_coverage,
        scope_limits=pipeline.LIMITS,
        elapsed_ms=round((time.monotonic() - start) * 1000),
    )
    history.finish(sid, result)
    return history.detail(sid)


def acknowledge(sid, fid):
    scan = history.detail(sid)
    if scan["trigger"] != "pre-push" or not any(
        h["id"] == fid and h["severity"] == "P2" for h in scan["findings"]
    ):
        raise ValueError("Expected a P2 finding from the named push scan")
    snap = scan["snapshot"]
    with history.database() as db:
        db.execute(
            "INSERT OR IGNORE INTO acknowledgements VALUES(?,?,?)",
            (snap["repository"], snap["sha256"], fid),
        )
        history.event(db, sid, "acknowledged " + fid)
    return {"finding": fid, "snapshot": snap["sha256"]}
