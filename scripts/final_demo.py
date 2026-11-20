"""Run the four-minute path in new disposable repositories. Only local bare remotes are used."""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from laundromat.history import home
from laundromat.workspace import FIXTURE

ENV = dict(
    os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0"
)


def run(repo, *argv, ok=True, env=None, stdin=None):
    p = subprocess.run(
        argv, cwd=repo, env=env or ENV, input=stdin, capture_output=True, text=True, timeout=180
    )
    if ok and p.returncode:
        raise RuntimeError(f"{argv[0]} {argv[1]} failed ({p.returncode}): " + p.stderr[:250])
    return p


def cli(repo, *args):
    return json.loads(run(repo, "laundromat", *args, "--json").stdout)


def git(repo, *args):
    return run(repo, "git", *args).stdout.strip()


def init(repo):
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "Laundromat review")
    git(repo, "config", "user.email", "review@example.invalid")


def commit(repo, msg):
    git(repo, "add", ".")
    git(repo, "commit", "-qm", msg)
    return git(repo, "rev-parse", "HEAD")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def push(repo, args, expected, env=None):
    start = time.monotonic()
    p = run(repo, "git", "push", "local", *args, ok=False, env=env)
    elapsed_ms = round((time.monotonic() - start) * 1000)
    output = p.stdout + p.stderr
    require(not re.search(r"\bLMTEST_[A-Z0-9]{20,32}\b", output), "Unredacted terminal output")
    match = re.search(r"pre-push · [a-z]+ · ([0-9a-f]{32})", output)
    require(match is not None, "Expected a persisted hook scan on a real push: " + output[:180])
    scan = cli(repo, "show", match[1])
    decision = scan["push_decision"]
    require(
        decision["action"] == expected and (p.returncode == 0) == (expected == "allow"),
        "Unexpected push outcome",
    )
    return dict(
        scan=scan["id"],
        action=expected,
        reason=decision["reason"],
        pending=decision["pending"],
        elapsed_ms=elapsed_ms,
        hook_ms=scan["elapsed_ms"],
        commits=scan["coverage"]["outgoing_commits"],
    )


def rehearse(base, extended=False, live=False):
    start = time.monotonic()
    repo = base / "catalog"
    init(repo)
    shutil.copytree(FIXTURE / "fixture", repo, dirs_exist_ok=True)
    commit(repo, "Synthetic search fixture")
    (repo / "notes.txt").write_text("Existing dirty notes\n")
    original = (repo / "search.js").read_bytes()
    args = ["capture", str(repo), "annotate-search"]
    if not live:
        args.append("--prepared")
    captured = cli(repo, *args)
    sid = captured["id"]
    current = (repo / "search.js").read_bytes()
    delta = captured["changes"]
    require(
        len(delta) == 1
        and delta[0]["before"] == hashlib.sha256(original).hexdigest()
        and delta[0]["after"] == hashlib.sha256(current).hexdigest(),
        "Capture delta/hash mismatch",
    )
    require(any("notes.txt" in d for d in captured["dirty_before"]), "Missing dirty input")
    r = captured["repair"]
    require(r["verdict"] == "verified", "Parameter binding gate failed")
    print(f"{captured['trigger']} · search.js:{r['line']} · {sid}\n{delta[0]['diff']}", flush=True)
    for phase in ("before", "after"):
        print(
            phase,
            r[phase]["binding"]["status"],
            [(x["term"], x["actual"]) for x in r[phase]["sqlite"]["results"]],
        )
    applied = cli(repo, "apply", sid)
    restored = cli(repo, "undo", sid)
    require(
        restored["sha256"] == r["original_sha256"] and (repo / "search.js").read_bytes() == current,
        "Undo mismatch",
    )
    print("Apply receipt", json.dumps(applied), "\nUndo receipt", json.dumps(restored), flush=True)

    outgoing = base / "outgoing"
    bare = base / "remote.git"
    init(outgoing)
    git(base, "init", "--bare", "-q", "-b", "main", str(bare))
    git(outgoing, "remote", "add", "local", str(bare))
    (outgoing / "notes.txt").write_text("Synthetic team repository\n")
    first = commit(outgoing, "Clean starting point")
    cli(outgoing, "install-hook", str(outgoing))
    initial = push(outgoing, ["main"], "allow")
    git(outgoing, "switch", "-qc", "intermediate")
    credential = "LMTEST_" + secrets.token_hex(12).upper()
    (outgoing / "settings.txt").write_text("test_key=" + credential + "\n")
    intermediate = commit(outgoing, "Synthetic configuration")
    (outgoing / "settings.txt").unlink()
    commit(outgoing, "Remove synthetic configuration")
    blocked = push(outgoing, ["HEAD:main"], "block")
    evidence = cli(outgoing, "show", blocked["scan"])
    require(
        any(h["evidence"].get("commit") == intermediate for h in evidence["findings"]),
        "Intermediate commit missed",
    )
    require(git(bare, "rev-parse", "main") == first, "Remote ref moved on blocked push")
    require(credential not in json.dumps(evidence), "Unredacted JSON")
    git(outgoing, "switch", "-q", "main")
    (outgoing / "notes.txt").write_text("Clean reviewed edit\n")
    final = commit(outgoing, "Clean reviewed edit")
    allowed = push(outgoing, ["main"], "allow")
    require(git(bare, "rev-parse", "main") == final, "Clean push failed to update remote")
    print(
        f"Blocked intermediate credential · remote main retained {first[:10]}\nClean push · main advanced to {final[:10]}",
        flush=True,
    )
    extra = {}
    if extended:
        (outgoing / "package-lock.json").write_text(
            json.dumps(
                {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.18"}}}
            )
        )
        commit(outgoing, "Recorded dependency")
        warning = push(outgoing, ["main"], "acknowledge")
        for fid in warning["pending"]:
            cli(outgoing, "acknowledge", warning["scan"], fid)
        accepted = push(outgoing, ["main"], "allow")
        (outgoing / "package-lock.json").write_text(
            json.dumps(
                {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.19"}}}
            )
        )
        tip = commit(outgoing, "Fixed advisory version")
        broken = base / "unavailable"
        broken.mkdir()
        stub = broken / "gitleaks"
        stub.write_text("#!/bin/sh\nexit 3\n")
        stub.chmod(0o755)
        outage = push(
            outgoing, ["main"], "block", {**ENV, "PATH": str(broken) + os.pathsep + ENV["PATH"]}
        )
        require(
            cli(outgoing, "show", outage["scan"])["status"] == "incomplete",
            "Tool failure presented as clean",
        )
        git(outgoing, "branch", "second")
        multi = push(outgoing, ["main", "second"], "allow")
        require(
            all(git(bare, "rev-parse", ref) == tip for ref in ("main", "second")),
            "Multi-ref update mismatch",
        )
        extra = dict(warning=warning, acknowledged=accepted, outage=outage, multi_ref=multi)
    from laundromat.history import database

    with database() as db:
        require(credential not in "\n".join(db.iterdump()), "Unredacted SQLite evidence")
        for file in home().glob("history.sqlite*"):
            require(credential.encode() not in file.read_bytes(), "Unredacted SQLite evidence")
    return dict(
        trigger=captured["trigger"],
        scan=sid,
        task_to_verdict_ms=captured["task_to_verdict_ms"],
        task_to_verified_patch_ms=captured["task_to_verified_patch_ms"],
        applied=applied["sha256"],
        restored=restored["sha256"],
        repair_ms=r["elapsed_ms"],
        first_push=initial,
        blocked=blocked,
        allowed=allowed,
        remote_before=first,
        remote_after=final,
        **extra,
        elapsed_ms=round((time.monotonic() - start) * 1000),
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--extended", action="store_true")
    p.add_argument("--live-agent", action="store_true")
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    results = []
    home().mkdir(parents=True, exist_ok=True)
    for _ in range(args.runs):
        base = Path(tempfile.mkdtemp(prefix="rehearsal-", dir=home()))
        results.append(rehearse(base, args.extended, args.live_agent))
    clean = [r[key]["action"] for r in results for key in ("first_push", "allowed")]
    report = dict(
        passed=len(results),
        runs=results,
        clean_branch_interruptions=sum(a != "allow" for a in clean),
        successful_clean_pushes=clean.count("allow"),
        scope="initial and clean main pushes in successful rehearsals",
    )
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"{len(results)}/{args.runs} rehearsals passed. Open /review/{results[-1]['scan']}/repair"
    )


if __name__ == "__main__":
    main()
