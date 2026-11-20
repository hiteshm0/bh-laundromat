"""Capture one fixture edit across a bounded task boundary."""

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from . import history
from .review import ORIGINAL, REPLACEMENT
from .snapshot import HEADER, ORIGINAL_HASH, delta, git, snapshot, trusted
from .workspace import atomic_write, digest, plain


def capture(repo, task, prepared=False, timeout=60, proposal=False, auto_apply=False):
    if task not in ("annotate-search", "bind-search"):
        raise ValueError("Supported tasks are annotate-search and bind-search")
    if auto_apply and not proposal:
        raise ValueError("--auto-apply requires --proposal")
    before, old = snapshot(repo)
    repo = Path(before["repository"])
    source = old.get("search.js", b"")
    if digest(source) != ORIGINAL_HASH:
        raise ValueError("Capture requires the original team-owned search.js")
    request = {
        "trigger": "prepared task replay" if prepared else "captured Codex edit",
        "snapshot": before,
        "before_snapshot": before,
        "task": task,
        "scope": None,
        "proposal": proposal,
        "pid": os.getpid(),
        "dirty_before": git(
            repo, "status", "--porcelain", "--untracked-files=all", "-z", "--", ".", check=False
        )
        .decode(errors="replace")
        .split("\0")[:-1],
        "attribution": "Changes observed during the task window may include concurrent edits.",
    }
    sid = history.submit(request, uuid.uuid4().hex, state="capturing")
    status, exit_code = "completed", None
    expected = (
        HEADER + source if task == "annotate-search" else source.replace(ORIGINAL, REPLACEMENT)
    )
    try:
        if prepared:
            candidate = expected
            exit_code = 0
        else:
            instruction = (
                "Add exactly this comment as the first line: " + HEADER.decode().strip()
                if task == "annotate-search"
                else "Parameterize the SQL with one ? and pass term to .all(term). Use double quotes for the SQL."
            )
            prompt = (
                instruction
                + '\nReturn JSON {"source":"complete file with trailing newline"}. No tools.\n'
                + source.decode()
            )
            with tempfile.TemporaryDirectory() as tmp:
                argv = [
                    "codex",
                    "exec",
                    "--ephemeral",
                    "--ignore-user-config",
                    "--disable",
                    "shell_tool",
                    "--disable",
                    "unified_exec",
                    "--sandbox",
                    "read-only",
                    "--skip-git-repo-check",
                    "--output-last-message",
                    str(Path(tmp) / "answer"),
                    "-",
                ]
                result = subprocess.run(
                    argv,
                    cwd=tmp,
                    input=prompt.encode(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                )
                exit_code = result.returncode
                if exit_code:
                    raise ValueError(f"Codex exited {exit_code}")
                candidate = json.loads((Path(tmp) / "answer").read_text())["source"].encode()
        if candidate != expected or not trusted(candidate):
            raise ValueError("Task returned an unsupported edit shape")
        path = plain(repo / "search.js")
        if path.read_bytes() != source:
            raise ValueError("Concurrent edit to search.js")
        if proposal:
            from .proposal import stage, decide

            stage(sid, request, old, candidate)
            if auto_apply and history.detail(sid).get("verified_actions"):
                try:
                    decide(sid, "accept", "automatic")
                except (OSError, ValueError) as exc:
                    with history.database() as db:
                        history.event(db, sid, "Automatic acceptance deferred: " + str(exc))
            return sid
        atomic_write(path, candidate, path.stat().st_mode & 0o777)
    except subprocess.TimeoutExpired:
        status = f"Codex timed out after {timeout} seconds"
    except KeyboardInterrupt:
        status = "Task interrupted by user"
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError):
        status = "Codex returned an invalid file response"
    except (OSError, ValueError) as exc:
        status = str(exc)
    finished = time.time()
    after, new = snapshot(repo)
    changes = delta(before, after, old, new)
    request.update(
        snapshot=after,
        changes=changes,
        scope=[c["path"] for c in changes],
        task_status=status,
        task_exit=exit_code,
        task_finished=finished,
    )
    with history.database() as db:
        db.execute(
            "UPDATE scans SET request=?,status='queued' WHERE id=?", (history.encoded(request), sid)
        )
        db.execute("UPDATE jobs SET state='queued' WHERE scan=?", (sid,))
        history.event(db, sid, "task finished" if status == "completed" else "task interrupted")
    return sid
