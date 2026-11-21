"""Run only the versioned, team-owned fixture tests. Repository text is never a command."""

import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .snapshot import trusted
from .workspace import FIXTURE, digest, json_bytes

SUITE_FILES = (
    "calibration/package.json",
    "cases.json",
    "observe.cjs",
    "owned.cjs",
    "seed.sql",
    "suite.json",
)
PROPERTIES = json.loads((FIXTURE / "suite.json").read_bytes())["tests"]
OWNED = json.loads((FIXTURE / "adapters/owned-v1.json").read_bytes())


def owned_bytes(test, phase):
    return OWNED[test][phase].replace("{{INERT}}", "Q" * 24).encode()


def approved(test, data):
    if test in OWNED:
        return data in (owned_bytes(test, "before"), owned_bytes(test, "after"))
    return trusted(data)


PIN = json.loads((FIXTURE / "image-pin.json").read_bytes())
IMAGE = PIN["image"]
MAX_OUTPUT = 32_768


def suite_digest():
    return digest(json_bytes({n: digest((FIXTURE / n).read_bytes()) for n in SUITE_FILES}))


def request(test_id, data=b""):
    return {
        "version": 1,
        "test_id": test_id,
        "suite_digest": suite_digest(),
        "timeout": 30,
        "input_hashes": {OWNED.get(test_id, {}).get("path", "search.js"): digest(data)}
        if data
        else {},
    }


def command(args, timeout, env=None):
    p = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
    if max(len(p.stdout), len(p.stderr)) > MAX_OUTPUT:
        raise ValueError("Verifier output exceeds size limit")
    if p.returncode:
        # Never forward daemon diagnostics containing host details.
        raise ValueError(
            f"{args[0]} {args[1]} failed (exit {p.returncode}): "
            + p.stderr.decode(errors="replace")[:240]
        )
    return p.stdout


def container_args(name):
    return [
        "docker",
        "create",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=32",
        "--cpus=0.5",
        "--memory=128m",
        "--memory-swap=128m",
        "--log-driver=none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=4m",
    ]


def remove_container(name, cid, remaining):
    command(["docker", "rm", "-f", name], remaining())
    present = command(
        [
            "docker",
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            "id=" + cid if cid and re.fullmatch(r"[0-9a-f]{64}", cid) else f"name=^/{name}$",
        ],
        remaining(),
    )
    if present.strip():
        raise ValueError("Container still present")


def report_verified_patch(callback, property_name, elapsed_ms):
    callback(f"[sandbox] Fixture verdict for {property_name} (original FAIL → candidate PASS)")
    callback("[sandbox] " + "━" * 45)
    callback(f"[sandbox] EXPLOIT CONFIRMED → PATCH VERIFIED in {elapsed_ms}ms")
    callback("[sandbox] " + "━" * 45)


def run(req, data=b"", mode="strict", progress_callback=None):
    start = time.monotonic()
    req = req if isinstance(req, dict) else {}
    test = req.get("test_id") if isinstance(req.get("test_id"), str) else None
    result = dict(
        property=PROPERTIES.get(test),
        status="incomplete",
        observations=None,
        input_hashes=req.get("input_hashes"),
        suite_digest=req.get("suite_digest"),
        runtime=IMAGE if mode == "strict" else "local compatibility",
        cleanup_status="no container created",
    )
    name = cid = None
    deadline = start + 30

    def remaining(reserve=0):
        left = deadline - time.monotonic() - reserve
        if left <= 0:
            raise ValueError("Fixture verification deadline exceeded")
        return left

    try:
        if (
            test not in PROPERTIES
            or set(req) != set(request(test, data))
            or type(req["version"]) is not int
            or req["version"] != 1
            or req["suite_digest"] != suite_digest()
            or (mode == "strict" and req["suite_digest"] != PIN["suite_digest"])
            or req["input_hashes"] != request(test, data)["input_hashes"]
            or type(req["timeout"]) is not int
            or not 1 <= req["timeout"] <= 30
        ):
            raise ValueError("Invalid verifier request or suite identity")
        if any(digest((FIXTURE / n).read_bytes()) != h for n, h in PIN["harness_hashes"].items()):
            raise ValueError("Changed fixture harness")
        if (test == "calibration" and data) or (test != "calibration" and not approved(test, data)):
            raise ValueError("Unsupported fixture bytes")
        deadline = min(deadline, start + req["timeout"])
        if mode == "local" and test not in ("binding", "sqlite"):
            raise ValueError("This adapter requires the immutable strict verifier")
        teardown_budget = min(3, req["timeout"] / 3)
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp).resolve() / "search.js"
            if data:
                sample.write_bytes(data)
                sample.chmod(0o444)
            if mode == "strict":
                # Inspect first so unavailable daemon/image yields an accurate no-create receipt.
                command(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE],
                    remaining(teardown_budget),
                )
                name = "laundromat-" + uuid.uuid4().hex
                args = container_args(name)
                if data:
                    args += [
                        "--mount",
                        f"type=bind,src={sample},dst=/sample/search.js,readonly",
                    ]
                cid = (
                    command(
                        [*args, IMAGE, test, "/sample/search.js"],
                        remaining(teardown_budget),
                    )
                    .decode()
                    .strip()
                )
                if not re.fullmatch(r"[0-9a-f]{64}", cid):
                    raise ValueError("Daemon returned an invalid container ID")
                result["container_id"] = cid
                if progress_callback:
                    progress_callback(f"[sandbox] Spinning up isolated container ({name})...")
                boot = time.monotonic()
                raw = command(["docker", "start", "--attach", cid], remaining(teardown_budget))
                result["warm_boot_ms"] = round((time.monotonic() - boot) * 1000)
                if progress_callback:
                    progress_callback(f"[sandbox] Container finished — start and run {result['warm_boot_ms']}ms")
            elif mode == "local":
                raw = command(
                    ["node", str(FIXTURE / "observe.cjs"), test, str(sample)],
                    remaining(),
                    env={"PATH": os.defpath + ":" + os.getenv("PATH", "")},
                )
            else:
                raise ValueError("Select strict or local compatibility mode")
            result.update(status="complete", observations=json.loads(raw))
            if test == "calibration" and result["observations"] != {
                "stages": ["fixture-install-stage", "v22.21.0"]
            }:
                raise ValueError("Unexpected Node calibration marker")
    except (KeyError, OSError, TypeError, ValueError, subprocess.TimeoutExpired) as exc:
        result.update(status="incomplete", reason=str(exc))
    finally:
        if name:
            try:
                remove_container(name, cid, remaining)
                result["cleanup_status"] = "removed"
            except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                result.update(
                    cleanup_status="unconfirmed",
                    status="incomplete",
                    reason=f"Container cleanup for {name}: {exc}",
                )
        result["duration_ms"] = round((time.monotonic() - start) * 1000)
    if progress_callback:
        if result["status"] == "complete":
            progress_callback(f"[sandbox] Observations collected ({result['duration_ms']}ms)")
        else:
            from .provider import redact

            progress_callback("[sandbox] ✗ Verifier error: " + redact(result["reason"]))
    return result


def run_node(files, entry_point, receipt):
    """Run the packaged Node verifier against files prevalidated by its caller."""
    start = time.monotonic()
    name = cid = None

    def remaining(reserve=0):
        budget = 30 - (time.monotonic() - start) - reserve
        if budget <= 0:
            raise ValueError("Container deadline exceeded")
        return budget

    try:
        command(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], remaining(4))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            for filename, data in files.items():
                path = folder / filename
                path.write_bytes(data)
                path.chmod(0o444)
            folder.chmod(0o755)
            name = "laundromat-" + uuid.uuid4().hex
            cmd = [
                *container_args(name),
                "--entrypoint=node",
                "--mount",
                f"type=bind,src={folder},dst=/input,readonly",
                IMAGE,
                "/input/" + entry_point,
            ]
            cid = command(cmd, remaining(4)).decode().strip()
            if not re.fullmatch(r"[0-9a-f]{64}", cid):
                raise ValueError("Invalid verifier container identity")
            receipt["container_id"] = cid
            raw = command(["docker", "start", "--attach", cid], remaining(4))
            state = command(
                [
                    "docker", "inspect", "--format",
                    "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", cid,
                ],
                remaining(4),
            )
            if state.strip() != b"exited 0 false":
                raise ValueError("Verifier process failed")
    except subprocess.TimeoutExpired:
        receipt.update(failure_kind="timeout", reason="Verifier timed out")
        raw = None
    except (OSError, ValueError) as exc:
        # Docker and Node diagnostics can include application source or daemon configuration.
        receipt.update(
            failure_kind="environment unavailable" if not cid else "execution failure",
            reason="Docker image or daemon unavailable"
            if not cid else f"Test execution failed ({type(exc).__name__})",
        )
        raw = None
    finally:
        if name:
            try:
                remove_container(name, cid, lambda: max(1, remaining()))
                receipt["cleanup_status"] = "removed"
            except (OSError, ValueError, subprocess.TimeoutExpired):
                receipt.update(cleanup_status="unconfirmed", reason="Container removal unconfirmed")
                raw = None
        receipt["duration_ms"] = round((time.monotonic() - start) * 1000)
    return raw
