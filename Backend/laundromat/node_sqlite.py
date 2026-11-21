"""Trusted Node/SQLite verifier for a configured, single-function query."""

import json
import re
from typing import Literal

from pydantic import Field, model_validator

from . import sandbox
from .inventory import Contract
from .snapshot import relative
from .workspace import ASSETS, digest, json_bytes

PROBE = ASSETS / "inventory/query-probe.cjs"
PROPERTY = "Constant SQL, separately bound search values, and correct ordered rows"
ASSERTIONS = ("constant_statement", "bound_value", "ordered_rows")
RULES = {"laundromat.composed-prepare", "laundromat.stock-query"}
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,47}")
SOURCE_PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:cjs|js)")
ORDINARY = re.compile(r"[A-Za-z0-9 ]{0,40}")
Scalar = str | int | float | None


class Case(Contract):
    term: str = Field(max_length=40)


class TestSpec(Contract):
    entry_point: str = Field(max_length=256)
    cases: list[Case] = Field(min_length=2, max_length=4)
    assertions: list[Literal["constant_statement", "bound_value", "ordered_rows"]] = Field(
        min_length=3, max_length=3
    )

    @model_validator(mode="after")
    def ordinary_cases(self):
        terms = [case.term for case in self.cases]
        if (
            set(self.assertions) != set(ASSERTIONS)
            or len(set(terms)) != len(terms)
            or any(ORDINARY.fullmatch(term) is None for term in terms)
        ):
            raise ValueError("Expected distinct ordinary search terms and all required assertions")
        return self


class QueryConfig(Contract):
    source: str = Field(max_length=200)
    export: str
    table: str
    columns: dict[str, Literal["TEXT", "INTEGER", "REAL"]] = Field(min_length=2, max_length=12)
    projection: list[str] = Field(min_length=1, max_length=12)
    filter_by: str
    match: Literal["exact", "contains"]
    order_by: str
    rows: list[dict[str, Scalar]] = Field(min_length=2, max_length=16)
    regression_terms: list[str] = Field(min_length=2, max_length=4)

    @model_validator(mode="after")
    def supported_fixture(self):
        if SOURCE_PATH.fullmatch(self.source) is None or relative(self.source) != self.source:
            raise ValueError("Expected a repository-relative JavaScript module")
        if any(
            IDENT.fullmatch(name) is None
            for name in (self.export, self.table, self.filter_by, self.order_by, *self.columns)
        ):
            raise ValueError("Unsupported JavaScript or SQL identifier")
        if (
            self.columns.get(self.filter_by) != "TEXT"
            or self.columns.get(self.order_by) not in ("INTEGER", "TEXT")
            or (self.projection != ["*"] and (
                self.order_by not in self.projection or not set(self.projection) <= self.columns.keys()
            ))
        ):
            raise ValueError("The fixture must expose a text filter and a projected ordering key")
        types = {"TEXT": (str,), "INTEGER": (int,), "REAL": (int, float)}
        for row in self.rows:
            if row.keys() != self.columns.keys() or any(
                value is not None and (type(value) not in types[self.columns[name]]
                or isinstance(value, str) and len(value) > 120)
                for name, value in row.items()
            ):
                raise ValueError("Fixture rows must match the declared columns")
        keys = [row[self.order_by] for row in self.rows]
        if None in keys or len(set(keys)) != len(keys):
            raise ValueError("Fixture ordering keys must be unique")
        if len(set(self.regression_terms)) != len(self.regression_terms) or any(
            ORDINARY.fullmatch(term) is None for term in self.regression_terms
        ):
            raise ValueError("Expected distinct ordinary regression terms")
        return self

    @property
    def entry_point(self):
        return self.source + "#" + self.export

    @property
    def statement(self):
        operator = "LIKE" if self.match == "contains" else "="
        return (
            f"SELECT {', '.join(self.projection)} FROM {self.table} "
            f"WHERE {self.filter_by} {operator} ? ORDER BY {self.order_by}"
        )

    def approved(self, data, *, bound=False):
        """Accept a single side-effect-free export with a bounded SQL statement."""
        if not data or len(data) > 2048:
            return False
        try:
            source = data.decode()
        except UnicodeError:
            return False
        module = re.fullmatch(
            rf"\s*exports\.{re.escape(self.export)}\s*=\s*function(?:\s+{re.escape(self.export)})?"
            r"\s*\(db,\s*term\)\s*\{\s*(?P<pattern>const pattern = `%\$\{term\}%`;\s*)?"
            r"return db\.prepare\((?P<expression>[^\r\n]+)\)\.all\((?P<args>[^\r\n]*)\);\s*\};\s*",
            source,
        )
        if module is None or bool(module["pattern"]) != (self.match == "contains"):
            return False
        expr, args = module["expression"], module["args"].strip()
        value = "pattern" if self.match == "contains" else "term"
        if quoted(expr, self.statement) and args == value:
            return True
        if bound or args:
            return False
        prefix, suffix = self.statement.split("?")
        return (
            expr == "`" + prefix + "'${" + value + "}'" + suffix + "`"
            or (match := re.fullmatch(r'(.+?)\s*\+\s*' + value + r'\s*\+\s*(.+)', expr))
            is not None and quoted(match[1], prefix + "'") and quoted(match[2], "'" + suffix)
        )

    def prompt(self):
        return dict(
            entry_point=self.entry_point,
            fixture=dict(
                rows=self.rows, order_by=self.order_by, filter_by=self.filter_by, match=self.match,
            ),
            required_assertions=ASSERTIONS,
            case_fields=("term",),
            case_description="Choose search terms. The SQLite verifier computes the expected rows.",
        )

    def observe(self, source, spec, test_hash, adapter_hash, config_hash, *, regress=False):
        probe = PROBE.read_bytes()
        result = dict(
            status="incomplete",
            runtime=sandbox.IMAGE,
            test_sha256=test_hash,
            adapter_sha256=digest(probe),
            regression_sha256=config_hash,
            source_sha256=digest(source),
            cleanup_status="no container created",
            operation="repository regression" if regress else "frozen property test",
        )
        if (
            not self.approved(source, bound=regress)
            or digest(probe) != adapter_hash
            or spec.entry_point != self.entry_point
            or digest(json_bytes(spec.model_dump())) != test_hash
        ):
            return dict(result, reason="Source or test differs from the approved query contract")
        plan = dict(
            config=self.model_dump(), statement=self.statement,
            cases=[{"term": term} for term in self.regression_terms] if regress
            else [case.model_dump() for case in spec.cases],
        )
        raw = sandbox.run_node(
            {"probe.cjs": probe, "subject.cjs": source, "plan.json": json_bytes(plan)},
            "probe.cjs", result,
        )
        if raw is None:
            return result
        try:
            observations = json.loads(raw)
            result["observations"] = observations
            if len(observations) != len(plan["cases"]) or any(
                not row["expected"] or len(row["calls"]) != 1 for row in observations
            ):
                return dict(result, status="unrelated assertion", reason="Expected rows or call count differ")
            result["status"] = "pass" if all(row["bound"] for row in observations) else "observed violation"
        except (ValueError, KeyError, TypeError):
            result["reason"] = "Invalid SQLite verifier output"
        return result


def quoted(expression, literal):
    return any(expression == quote + literal + quote for quote in ('"', "'", "`"))
