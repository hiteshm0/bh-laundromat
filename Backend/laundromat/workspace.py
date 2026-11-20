"""Storage shared by the CLI commands, scoped to this editable checkout."""

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "demo"
LAB = ROOT / ".laundromat"
WORK = LAB / "workspace"
RUNS = LAB / "runs"
SEARCH = "search.js"
CONTROL = "safe-search.js"
SOURCES = (SEARCH, CONTROL)
MARKER = LAB / ".phase1-workspace"


class Refused(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def plain(path: Path) -> Path:
    if path.resolve() != path or not path.is_file():
        raise Refused(f"Expected a regular file at {path}")
    return path


def directory(path: Path) -> Path:
    if path.resolve() != path or not path.is_dir():
        raise Refused(f"Expected a workspace directory at {path}")
    return path


@contextmanager
def workspace_lock():
    # A directory lock survives reset and serializes CLI writers without a lock file.
    fd = os.open(ROOT, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def require_lab():
    if not LAB.exists():
        raise Refused("Run 'laundromat setup' to create the disposable workspace.")
    if plain(MARKER).read_bytes() != b"laundromat phase 1\n":
        raise Refused(f"Unrecognized workspace at {LAB}")


def setup(reset: bool):
    if LAB.is_symlink():
        raise Refused(f"Refusing a symlink at {LAB}")
    if LAB.exists():
        require_lab()
        if not reset:
            return
    # Keep the previous workspace intact until the replacement is ready.
    with tempfile.TemporaryDirectory(dir=ROOT, prefix=".laundromat-setup-") as tmp:
        staged = Path(tmp) / "lab"
        shutil.copytree(FIXTURE / "fixture", staged / WORK.name)
        (staged / RUNS.name).mkdir()
        (staged / MARKER.name).write_bytes(b"laundromat phase 1\n")
        previous = Path(tmp) / "previous"
        if LAB.exists():
            LAB.rename(previous)
        try:
            staged.rename(LAB)
        except OSError:
            if previous.exists():
                previous.rename(LAB)
            raise


def atomic_write(path: Path, data: bytes, mode: int = 0o600):
    fd, name = tempfile.mkstemp(dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
