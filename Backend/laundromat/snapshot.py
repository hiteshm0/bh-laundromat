"""Local Git snapshots. Persist hashes for arbitrary files and display text only for the team fixture."""

import difflib
import os
import re
import subprocess
from pathlib import Path

from .workspace import digest, json_bytes, plain

TOKEN = re.compile(
    r"(?:LMTEST_[A-Za-z0-9_-]+|(?:ghp_|github_pat_|sk-proj-|gsk_)[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16})"
)
IGNORE = {".git", ".venv", "node_modules", ".laundromat", ".laundromat-history", "__pycache__"}
LIMIT = 2_000_000
HEADER = b"// Search the synthetic swatch catalog.\n"
# Fixed fixture identities, independent of the contents of a scanned checkout.
ORIGINAL_HASH = "2ff4c4305367223fe57bdc351cb27f7189dc2f44a637ad78e5fb452f4885a475"
SAFE_HASH = "abd990ba91465f1fb27c4bf5b4a790c081c6871ab21885e42a4b56b9af4e818c"


def trusted(data):
    body = data.removeprefix(HEADER)
    sql = b"SELECT id FROM swatches WHERE color = ? ORDER BY id"
    body = body.replace(b"'" + sql + b"'", b'"' + sql + b'"')
    return digest(body) in (ORIGINAL_HASH, SAFE_HASH)


def git(repo, *args, check=True):
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR")
    }
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(repo), *args],
        env=env,
        capture_output=True,
        timeout=30,
    )
    if check and result.returncode:
        raise ValueError(f"git {args[0]} failed (exit {result.returncode})")
    return result.stdout


def relative(name):
    p = Path(name)
    if not p.parts or p.is_absolute() or ".." in p.parts or set(p.parts) & IGNORE:
        raise ValueError("Path outside supported scope")
    if TOKEN.search(name) or any(ord(c) < 32 for c in name):
        raise ValueError("A path contains sensitive or unsupported characters")
    return p.as_posix()


def snapshot(repo, scope=None, *, allow_absent=False):
    repo = Path(repo).resolve(strict=True)
    if not repo.is_dir() or TOKEN.search(str(repo)):
        raise ValueError("Expected a local repository directory")
    revision = git(repo, "rev-parse", "--verify", "HEAD", check=False).decode().strip() or None
    contents, hashes, issues = {}, {}, []
    if scope is None:
        if git(repo, "rev-parse", "--show-toplevel", check=False).strip() == os.fsencode(repo):
            paths = [
                os.fsdecode(p)
                for p in git(
                    repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
                ).split(b"\0")
                if p
            ]
        else:
            paths = []

            def unreadable(exc):
                issues.append(TOKEN.sub("[redacted]", f"Directory enumeration failed: {exc}"))

            for base, dirs, files in os.walk(repo, onerror=unreadable):
                dirs[:] = [d for d in dirs if d not in IGNORE]
                paths.extend(str((Path(base) / f).relative_to(repo)) for f in files)
    else:
        paths = scope
    unique = sorted(set(paths))
    if len(unique) > 4096:
        issues.append("Snapshot exceeds the 4096-path limit")
    total_bytes = 0
    for name in unique[:4096]:
        if set(Path(name).parts) & IGNORE:
            if scope is not None:
                issues.append(
                    "Explicit path is outside supported scope: " + TOKEN.sub("[redacted]", name)
                )
            continue
        try:
            path = repo / relative(name)
            if not path.exists() and not path.is_symlink():
                hashes[name] = None
                if scope is not None and not allow_absent:
                    issues.append("Requested file is missing: " + name)
                continue
            if plain(path).stat().st_size > LIMIT:
                raise ValueError("exceeds 2 MB file limit")
            total_bytes += path.stat().st_size
            if total_bytes > 32_000_000:
                issues.append("Snapshot exceeds the 32 MB limit")
                break
            contents[name] = path.read_bytes()
            hashes[name] = digest(contents[name])
        except (OSError, ValueError) as exc:
            issues.append(TOKEN.sub("[redacted]", f"{name}: {exc}"))
    marker = repo.stat()
    identity = {
        "repository": str(repo),
        "directory_id": [marker.st_dev, marker.st_ino],
        "revision": revision,
        "files": hashes,
        "issues": issues,
    }
    return {**identity, "sha256": digest(json_bytes(identity))}, contents


def delta(before, after, old, new):
    changes = []
    for name in sorted(before["files"].keys() | after["files"].keys()):
        left, right = before["files"].get(name), after["files"].get(name)
        if left == right:
            continue
        kind = "added" if left is None else "deleted" if right is None else "modified"
        a, b = old.get(name, b""), new.get(name, b"")
        display = "Content withheld; compare the recorded hashes."
        if name == "search.js" and all(not data or trusted(data) for data in (a, b)):
            display = "".join(
                difflib.unified_diff(
                    a.decode().splitlines(True),
                    b.decode().splitlines(True),
                    fromfile="a/" + name,
                    tofile="b/" + name,
                )
            )
        changes.append(dict(path=name, change=kind, before=left, after=right, diff=display))
    return changes
