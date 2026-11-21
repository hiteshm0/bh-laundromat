"""Approved Node/SQLite inventory contract. All executable inputs have a bounded grammar or a pinned digest."""

import difflib
import json
import re
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
    if (
        not approved(source)
        or digest(regression) != REGRESSION_HASH
        or digest(frozen) != test_hash
        or digest(probe) != adapter_hash
    ):
        return dict(
            result, duration_ms=0, failure_kind="identity mismatch",
            reason="Source, test or adapter identity changed",
        )
    raw = sandbox.run_node(
        {"probe.cjs": probe, "stock.cjs": source, "stock.test.cjs": regression, "test.json": frozen},
        "stock.test.cjs" if regress else "probe.cjs",
        result,
    )
    if raw is None:
        return result
    if regress:
        return dict(result, status="pass")
    try:
        rows = json.loads(raw)
        result["observations"] = rows
        if len(rows) != len(spec.cases) or any(
            row["term"] != c.term or row["skus"] != c.expected_skus or len(row["calls"]) != 1
            for row, c in zip(rows, spec.cases)
        ):
            return dict(result, status="unrelated assertion", reason="Ordinary row or call-count regression")
        calls = [row["calls"][0] for row in rows]
        bound = len({call["sql"] for call in calls}) == 1 and all(
            call["args"] == [case.term] for call, case in zip(calls, spec.cases)
        )
        result["status"] = "pass" if bound else "observed violation"
    except (KeyError, TypeError, ValueError, IndexError):
        result.update(failure_kind="execution failure", reason="Invalid SQLite verifier output")
    return result
