"""Approved Node/SQLite inventory contract. All executable inputs have a bounded grammar or a pinned digest."""

import difflib
import json
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import sandbox
from .workspace import ASSETS, digest, json_bytes

SOURCE = "inventory/stock.cjs"
REGRESSION = "inventory/stock.test.cjs"
REGRESSION_HASH = "80a1d81bb38a067c009494dbb3141a14e8a413aa30a8253cc1379e42fa066097"
PROBE = ASSETS / "inventory/probe.cjs"
PROPERTY = "Constant inventory SELECT with a bound aisle and correct ordered SKUs"
SEED = {"north": ["P1", "P3"], "south": ["P2"], "empty": []}
ASSERTIONS = ("constant_statement", "bound_aisle", "ordered_skus")

# This single-export service accepts no imports, side effects, or auxiliary statements.
MODULE = re.compile(
    rb"\s*exports\.byAisle\s*=\s*function byAisle\(db, aisle\)\s*\{\s*"
    rb"return db\.prepare\(([\x22'`])SELECT sku FROM stock WHERE aisle = "
    rb"(\?|'\$\{aisle\}')( ORDER BY sku)?\1\)\.all\((aisle)?\);\s*\};\s*"
)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class Case(Contract):
    term: Literal["north", "south", "empty"]
    expected_skus: list[str] = Field(max_length=2)


class TestSpec(Contract):
    entry_point: Literal["inventory/stock.cjs#byAisle"]
    cases: list[Case] = Field(min_length=2, max_length=3)
    assertions: list[Literal["constant_statement", "bound_aisle", "ordered_skus"]] = Field(
        max_length=3
    )

    @model_validator(mode="after")
    def grounded_expectations(self):
        if set(self.assertions) != set(ASSERTIONS) or len({c.term for c in self.cases}) != len(
            self.cases
        ):
            raise ValueError("Test needs all contract observations and distinct ordinary inputs")
        if any(c.expected_skus != SEED[c.term] for c in self.cases):
            raise ValueError("Expected rows disagree with the immutable seed")
        return self


def approved(data):
    return len(data) <= 2048 and MODULE.fullmatch(data) is not None


def diff(path, before, after, *, context=3):
    return "".join(
        difflib.unified_diff(
            before.decode().splitlines(True),
            after.decode().splitlines(True),
            fromfile="a/" + path,
            tofile="b/" + path,
            n=context,
        )
    )


def execute(source, regression, spec, test_hash, adapter_hash, *, regress=False):
    frozen = json_bytes(spec.model_dump())
    probe = PROBE.read_bytes()
    result = dict(
        status="incomplete",
        runtime=sandbox.IMAGE,
        test_sha256=test_hash,
        adapter_sha256=digest(probe),
        regression_sha256=digest(regression),
        source_sha256=digest(source),
        cleanup_status="no container created",
        operation="repository regression" if regress else "frozen property test",
    )
    start = time.monotonic()
    name = cid = None

    def remaining(reserve=0):
        timeout = 30 - (time.monotonic() - start) - reserve
        if timeout <= 0:
            raise ValueError("Container deadline exceeded")
        return timeout

    try:
        if (
            not approved(source)
            or digest(regression) != REGRESSION_HASH
            or digest(frozen) != test_hash
            or digest(probe) != adapter_hash
        ):
            result.update(
                failure_kind="identity mismatch", reason="Source, test or adapter identity changed"
            )
            return result
        sandbox.command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", sandbox.IMAGE],
            remaining(4),
        )
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            for filename, data in (
                ("probe.cjs", probe),
                ("stock.cjs", source),
                ("stock.test.cjs", regression),
                ("test.json", frozen),
            ):
                (folder / filename).write_bytes(data)
                (folder / filename).chmod(0o444)
            folder.chmod(0o755)
            name = "laundromat-" + uuid.uuid4().hex
            cmd = [
                *sandbox.container_args(name),
                "--entrypoint=node",
                "--mount",
                f"type=bind,src={folder},dst=/input,readonly",
                sandbox.IMAGE,
                "/input/stock.test.cjs" if regress else "/input/probe.cjs",
            ]
            cid = sandbox.command(cmd, remaining(4)).decode().strip()
            if not re.fullmatch(r"[0-9a-f]{64}", cid):
                raise ValueError("Invalid verifier container identity")
            result["container_id"] = cid
            raw = sandbox.command(["docker", "start", "--attach", cid], remaining(4))
            state = sandbox.command(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}",
                    cid,
                ],
                remaining(4),
            )
            if state.strip() != b"exited 0 false":
                raise ValueError("Verifier process failed")
            if regress:
                result.update(status="pass")
            else:
                rows = json.loads(raw)
                result["observations"] = rows
                if len(rows) != len(spec.cases) or any(
                    row["term"] != c.term
                    or row["skus"] != c.expected_skus
                    or len(row["calls"]) != 1
                    for row, c in zip(rows, spec.cases)
                ):
                    result.update(
                        status="unrelated assertion",
                        reason="Ordinary row or call-count regression",
                    )
                else:
                    calls = [row["calls"][0] for row in rows]
                    bound = len({c["sql"] for c in calls}) == 1 and all(
                        c["args"] == [case.term] for c, case in zip(calls, spec.cases)
                    )
                    result.update(status="pass" if bound else "observed violation")
    except subprocess.TimeoutExpired:
        result.update(failure_kind="timeout", reason="Verifier timed out")
    except (OSError, TypeError, KeyError, ValueError, IndexError) as exc:
        # Diagnostics from Node or Docker may contain application source or daemon configuration.
        result.update(
            failure_kind="environment unavailable" if not cid else "execution failure",
            reason="Docker image or daemon unavailable"
            if not cid
            else f"Test execution failed ({type(exc).__name__})",
        )
    finally:
        if name:
            try:
                sandbox.remove_container(name, cid, lambda: max(1, remaining()))
                result["cleanup_status"] = "removed"
            except (OSError, ValueError, subprocess.TimeoutExpired):
                result.update(
                    status="incomplete",
                    cleanup_status="unconfirmed",
                    reason="Container removal unconfirmed",
                )
        result["duration_ms"] = round((time.monotonic() - start) * 1000)
    return result
