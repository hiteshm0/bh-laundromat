"""LangGraph push controller. Graph channels carry identities, evidence stays in the local ledger."""

import difflib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Literal

from langgraph.graph import END, START, StateGraph
from langsmith import tracing_context
from pydantic import Field, ValidationError
from typing_extensions import TypedDict

from . import detect, experiment, gate, history, inventory, provider, push_stage
from .snapshot import git
from .workspace import digest, json_bytes

ERRORS = (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError)
MAX_CALLS = 9
POLICY = detect.RULES / "push.rego"


class PushState(TypedDict, total=False):
    scan: str
    mode: str
    bases: list[str]
    tips: list[str]
    findings: list[str]
    reuse: bool


class FindingState(TypedDict, total=False):
    finding: str
    test_hash: str
    outcome: str


class Triage(inventory.Contract):
    path: str = Field(max_length=512)
    line: int | None
    reasoning: str = Field(min_length=1, max_length=500)
    property: str = Field(min_length=1, max_length=300)
    route: Literal["runtime", "static"]


class Patch(inventory.Contract):
    path: Literal["inventory/stock.cjs"]
    old_line: str = Field(min_length=1, max_length=512)
    new_line: str = Field(min_length=1, max_length=512)
    rationale: str = Field(min_length=1, max_length=400)


def display_source(data):
    # Only the reviewed service grammar can expose literals. Other source excerpts
    # retain line structure and mask literal values, identifiers and comments.
    if inventory.approved(data):
        return data.decode()
    return "\n".join(
        re.sub(r"[\w$]+|(['\"`]).*?\1|//.*|/\*.*", "…", line)[:200]
        for line in data.decode(errors="replace").splitlines()
    )


def object_bytes(repo, oid, path):
    if oid.strip("0"):
        obj = oid + ":" + path
        size = git(repo, "cat-file", "-s", obj, check=False).strip()
        if size and int(size) <= 2_000_000:
            return git(repo, "cat-file", "blob", obj)
    return b""


def location(repo, h, tips, commits):
    path, line, commit = h["path"], h["line"], h["evidence"]["commit"]
    base = h["evidence"].get("base", "")
    if path == "(commit message)":
        return {
            "change": "outgoing-tip" if commit in tips else "intermediate-history",
            "introducing_commit": commit,
        }, b""
    source = object_bytes(repo, commit, path)
    if not source and h["category"] == "metadata":
        return {"change": "recorded metadata"}, b""
    if line is not None and not 1 <= line <= len(source.splitlines()):
        raise ValueError("Scanner location outside the reviewed Git blob")
    before = object_bytes(repo, base, path)
    change = "introduced"
    intro = commit
    if line:
        blame = (
            git(
                repo,
                "blame",
                "--no-textconv",
                "--line-porcelain",
                "-L",
                f"{line},{line}",
                commit,
                "--",
                path,
            )
            .splitlines()[0]
            .split()
        )
        intro = blame[0].decode()
        if intro not in commits or (
            base.strip("0")
            and git(repo, "merge-base", base, intro, check=False).strip() == intro.encode()
        ):
            change = "pre-existing"
    elif before == source or (
        h["category"] == "dependency"
        and before
        and any(
            old["rule"] == h["rule"]
            and old["evidence"]
            == {k: v for k, v in h["evidence"].items() if k not in ("base", "commit")}
            for old in detect.dependencies(before, path)
        )
    ):
        change = "pre-existing"
    info = dict(change=change, introducing_commit=intro)
    if h["category"] == "secret" and commit not in tips:
        info.update(origin=change, change="intermediate-history")
    if change != "pre-existing":
        parent = git(repo, "rev-parse", "--verify", intro + "^", check=False).decode().strip()
        old = object_bytes(repo, parent, path)
        new = object_bytes(repo, intro, path)
        if max(len(old), len(new)) <= 32_768:
            # Generate the hunk from real bytes, then mask content for display.
            raw = difflib.unified_diff(
                old.decode(errors="replace").splitlines(),
                new.decode(errors="replace").splitlines(),
                fromfile="a/" + path,
                tofile="b/" + path,
                lineterm="",
                n=2,
            )
            safe = all(not data or inventory.approved(data) for data in (old, new))
            lines = []
            for index, row in enumerate(raw):
                if index < 2 or row.startswith("@@") or safe:
                    lines.append(row)
                else:
                    lines.append(row[:1] + "[redacted source]")
            info["introducing_diff"] = provider.redact("\n".join(lines))[:3000]
    return info, source


def policy_routes(inputs):
    p = subprocess.run(
        [
            "opa",
            "eval",
            "--format=raw",
            "--stdin-input",
            "--data",
            str(POLICY),
            "[r | some x in input; r := data.laundromat.push.route with input as x]",
        ],
        input=json_bytes(inputs),
        capture_output=True,
        timeout=8,
    )
    if p.returncode:
        raise ValueError("OPA could not evaluate the packaged push policy")
    routes = json.loads(p.stdout)
    if len(routes) != len(inputs) or any(
        r not in {"block", "acknowledge", "runtime", "triage", "static"} for r in routes
    ):
        raise ValueError("OPA returned invalid finding routes")
    return routes


class PushReview:
    def __init__(self, repo, remote, lines, progress=None):
        self.repo, self.remote, self.lines = repo, remote, lines
        self.progress = progress
        self.mode = gate.mode(repo)
        self.started = time.monotonic()
        self.calls = 0
        self.issues = []
        self.items = {}
        self.hits = {}

    def report(self, stage):
        if self.progress is not None:
            self.progress(stage)

    def collect(self, state):
        try:
            self.updates, self.commits, tips = gate.commits_for(self.repo, self.remote, self.lines)
        except ERRORS as exc:
            self.updates, self.commits, tips = [], [], []
            self.issues.append("Required scan incomplete: " + str(exc))
        identity = digest(
            json_bytes(
                [
                    self.updates,
                    self.commits,
                    tips,
                    self.issues,
                    digest(self.lines.encode()),
                    digest(POLICY.read_bytes()),
                    provider.PUSH_ROLES,
                    inventory.sandbox.IMAGE,
                    digest(inventory.PROBE.read_bytes()),
                    {p.name: digest(p.read_bytes()) for p in detect.RULES.iterdir() if p.is_file()},
                    provider.selected(),
                    os.getenv("LAUNDROMAT_MODEL"),
                ]
            )
        )
        req = dict(
            trigger="pre-push",
            mode=self.mode,
            scope=self.commits,
            updates=self.updates,
            snapshot=dict(
                repository=str(self.repo),
                revision=tips,
                sha256=identity,
                files={},
                issues=[],
            ),
        )
        self.sid = history.submit(req, state="deciding")
        prior = history.detail(self.sid)
        reuse = bool(
            prior.get("workflow_version") == 1
            and prior["status"] == "findings"
            and prior.get("proposal_ready")
        )
        if not reuse:
            with history.database() as db:
                req["pid"] = os.getpid()
                db.execute(
                    "UPDATE scans SET request=?,status='deciding',result=NULL WHERE id=?",
                    (history.encoded(req), self.sid),
                )
                db.execute(
                    "UPDATE jobs SET state='deciding',attempts=attempts+1 WHERE scan=?",
                    (self.sid,),
                )
                for table in ("findings", "previews", "push_evidence"):
                    db.execute(f"DELETE FROM {table} WHERE scan=?", (self.sid,))
        push_stage.observe_commits(self.repo, self.updates)
        return dict(
            scan=self.sid,
            bases=sorted({u["base"] for u in self.updates}),
            tips=tips,
            reuse=reuse,
        )

    def scan(self, state):
        self.report("scan")
        req, self.result = gate.scan_objects(
            self.repo, self.updates, self.commits, state["tips"], self.issues
        )
        req.update(mode=self.mode, pid=os.getpid())
        with history.database() as db:
            db.execute(
                "UPDATE scans SET request=? WHERE id=?",
                (history.encoded(req), self.sid),
            )
        inputs = []
        for h in self.result["findings"]:
            commit = h["evidence"]["commit"]
            # Identical findings across ref updates share a row only for identical evidence.
            fid = digest(json_bytes([h["id"], commit, h["evidence"].get("base")]))[:24]
            if fid in self.hits:
                continue
            h["scanner_id"], h["id"] = h["id"], fid
            self.hits[fid] = h
            item = dict(
                finding_id=fid,
                path=h["path"],
                commit=commit,
                state="flagged",
                role_calls=[],
            )
            self.items[fid] = item
            try:
                loc, source = location(self.repo, h, state["tips"], self.commits)
                item.update(loc)
                h["change"] = loc["change"]
                supported = (
                    h["path"] == inventory.SOURCE
                    and h["rule"] == "laundromat.stock-query"
                    and inventory.approved(source)
                )
                if (
                    supported
                    and digest(object_bytes(self.repo, commit, inventory.REGRESSION))
                    != inventory.REGRESSION_HASH
                ):
                    raise ValueError("Approved repository regression is missing or changed")
            except ERRORS as exc:
                self.issues.append("Evidence location unavailable: " + str(exc))
                item.update(change="unknown")
                supported = False
            inputs.append(
                dict(
                    category=h["category"],
                    rule=h["rule"],
                    supported=supported,
                    change=item["change"],
                )
            )
        self.result["findings"] = list(self.hits.values())
        try:
            routes = policy_routes(inputs) if state["tips"] else []
            for (fid, item), route in zip(self.items.items(), routes, strict=True):
                item["policy_route"] = route
                if route in ("block", "acknowledge"):
                    self.hits[fid]["push_policy"] = route
        except ERRORS as exc:
            self.issues.append("Team policy incomplete: " + str(exc))
        self.result["versions"]["push_policy_sha256"] = digest(POLICY.read_bytes())
        for item in self.items.values():
            push_stage.record(self.sid, item)
        self.static_incomplete = bool(self.issues)
        return {"findings": list(self.hits)}

    def call(self, name, schema, artifact, item):
        trace = item["role_calls"]
        left = 150 - (time.monotonic() - self.started)
        if self.calls >= MAX_CALLS or left < 1:
            raise ValueError("Push review call or time budget exhausted")
        self.calls += 1
        try:
            parsed = experiment.independent_call(
                name, artifact, trace, schema=schema, timeout=min(25, left)
            )
            trace[-1]["outcome"] = "valid"
            return parsed
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            if trace:
                trace[-1]["outcome"] = (
                    "invalid" if isinstance(exc, ValidationError) else "unavailable"
                )
            if isinstance(exc, ValidationError):
                raise ValueError(f"{name} returned an invalid artifact") from exc
            raise

    def finding_graph(self):
        def run_node(fn):
            def run(state):
                item = self.items[state["finding"]]
                try:
                    update = fn(self.hits[state["finding"]], item)
                except ERRORS as exc:
                    reason = provider.redact(str(exc))[:320]
                    item.update(state="inconclusive", reason=reason)
                    self.issues.append(f"{item['path']}: {reason}")
                    update = {"outcome": "stop"}
                push_stage.record(self.sid, item)
                return update

            return run

        def triage(h, item):
            route = item.get("policy_route")
            if route is None or self.static_incomplete:
                item.update(state="inconclusive", reason="Required static coverage incomplete")
                return {"outcome": "stop"}
            if route not in ("triage", "runtime"):
                item["reason"] = "Static evidence sufficient under team policy: " + route
                return {"outcome": "stop"}
            self.report("review")
            source = object_bytes(self.repo, item["commit"], h["path"])
            line = h["line"] or 1
            nearby = display_source(source).splitlines()[max(0, line - 4) : line + 3]
            answer = self.call(
                "Detect",
                Triage,
                dict(
                    path=h["path"],
                    line=h["line"],
                    evidence={
                        k: h[k]
                        for k in (
                            "rule",
                            "category",
                            "explanation",
                            "severity",
                            "source",
                        )
                    },
                    context=nearby,
                    introducing_diff=item.get("introducing_diff"),
                    change=item["change"],
                    policy="Runtime binding contract required"
                    if route == "runtime"
                    else "Static review only",
                ),
                item,
            )
            if answer.path != h["path"] or answer.line != h["line"]:
                raise ValueError("Detect location disagrees with the outgoing scanner evidence")
            item["detect"] = answer.model_dump()
            if route == "triage":
                item["reason"] = "Static finding; no approved runtime adapter for this source"
                return {"outcome": "stop"}
            if answer.route != "runtime":
                raise ValueError("Detect did not support the required runtime review")
            return {"outcome": "prove"}

        def prove(h, item):
            self.report("original")
            source = object_bytes(self.repo, item["commit"], h["path"])
            spec = self.call(
                "Prove",
                inventory.TestSpec,
                dict(
                    finding=item["detect"],
                    source=source.decode(),
                    entry_point=inventory.SOURCE + "#byAisle",
                    seed=inventory.SEED,
                    required_assertions=inventory.ASSERTIONS,
                ),
                item,
            )
            item["adapter_sha256"] = digest(inventory.PROBE.read_bytes())
            item["test"] = spec.model_dump()
            item["test_sha256"] = digest(json_bytes(item["test"]))
            return {"outcome": "original", "test_hash": item["test_sha256"]}

        def observe(h, item, candidate=False, regress=False):
            original = object_bytes(self.repo, item["commit"], h["path"])
            regression = object_bytes(self.repo, item["commit"], inventory.REGRESSION)
            return inventory.execute(
                item["candidate"].encode() if candidate else original,
                regression,
                inventory.TestSpec.model_validate(item["test"]),
                item["test_sha256"],
                item["adapter_sha256"],
                regress=regress,
            )

        def original(h, item):
            result = item["before"] = observe(h, item)
            if result["status"] == "observed violation":
                return {"outcome": "fix"}
            if result["status"] != "pass":
                raise ValueError(result.get("reason", result["status"]))
            item["reason"] = "Original satisfied the frozen property test"
            return {"outcome": "stop"}

        def fix(h, item):
            self.report("draft")
            src = object_bytes(self.repo, item["commit"], h["path"])
            answer = self.call(
                "Fix",
                Patch,
                dict(
                    path=h["path"],
                    line=h["line"],
                    source=src.decode(),
                    property=inventory.PROPERTY,
                    observations=item["before"]["observations"],
                    permitted_edit="One return statement at the reported line",
                ),
                item,
            )
            lines = src.decode().splitlines(keepends=True)
            n = h["line"] - 1
            if (
                lines[n].removesuffix("\n") != answer.old_line
                or not answer.new_line.strip().startswith("return ")
                or len(answer.new_line.splitlines()) != 1
                or answer.old_line == answer.new_line
            ):
                raise ValueError("Patch does not replace exactly the reported return statement")
            lines[n] = answer.new_line + ("\n" if lines[n].endswith("\n") else "")
            candidate = "".join(lines).encode()
            if not inventory.approved(candidate):
                raise ValueError("Candidate exceeds the approved inventory service grammar")
            patch = inventory.diff(h["path"], src, candidate)
            item.update(
                candidate=candidate.decode(),
                patch=patch,
                patch_sha256=digest(patch.encode()),
                candidate_sha256=digest(candidate),
                original_sha256=digest(src),
                rationale=answer.rationale,
            )
            return {"outcome": "candidate"}

        def candidate(h, item):
            self.report("verify")
            after = item["after"] = observe(h, item, candidate=True)
            if after["status"] != "pass":
                raise ValueError(
                    "Candidate failed the frozen test: " + after.get("reason", after["status"])
                )
            result = item["regression"] = observe(h, item, candidate=True, regress=True)
            if result["status"] != "pass":
                raise ValueError(
                    "Repository regression failed: " + result.get("reason", result["status"])
                )
            candidate_bytes = item["candidate"].encode()
            found, version = detect.queries({h["path"]: candidate_bytes})
            secrets = detect.secrets(candidate_bytes, h["path"])
            item["rescan"] = dict(
                semgrep=version,
                query_matches=len(found),
                credential_matches=len(secrets),
            )
            if found or secrets:
                raise ValueError("Candidate detector recheck retained findings")
            item.update(state="verified", verified=True, property=inventory.PROPERTY)
            return {"outcome": "stop"}

        graph = StateGraph(FindingState)
        for node, fn in (
            ("detect", triage),
            ("prove", prove),
            ("original", original),
            ("fix", fix),
            ("candidate", candidate),
        ):
            graph.add_node(node, run_node(fn))
        graph.add_edge(START, "detect")
        for node, successor in (
            ("detect", "prove"),
            ("prove", "original"),
            ("original", "fix"),
            ("fix", "candidate"),
        ):
            graph.add_conditional_edges(
                node, lambda s: s["outcome"], {"stop": END, successor: successor}
            )
        graph.add_edge("candidate", END)
        return graph.compile()

    def review(self, state):
        graph = self.finding_graph()
        for fid in state["findings"]:
            graph.invoke({"finding": fid}, {"recursion_limit": 8})
        return {}

    def aggregate(self, state):
        result = self.result
        pending = []
        snap = history.detail(self.sid)["snapshot"]
        with history.database() as db:
            acknowledged = {
                r[0]
                for r in db.execute(
                    "SELECT finding FROM acknowledgements WHERE repo=? AND snapshot=?",
                    (str(self.repo), snap["sha256"]),
                )
            }
        for fid, h in self.hits.items():
            item = self.items[fid]
            h["state"] = item["state"]
            h["repair_status"] = item.get("reason", item["state"])
            if h["push_policy"] == "acknowledge" and not {fid, h["scanner_id"]} & acknowledged:
                pending.append(fid)
            if item.get("verified"):
                h["property"] = item["property"]
                item["state"] = "proposed"
                push_stage.record(self.sid, item)
                result["verified_actions"].append(
                    dict(
                        finding_id=fid,
                        path=h["path"],
                        property=item["property"],
                        sha256=item["candidate_sha256"],
                    )
                )
        result["raw_candidates"] = [
            {k: h[k] for k in ("id", "category", "rule", "path", "line", "severity")}
            for h in self.hits.values()
        ]
        result["unsupported_checks"] = [
            item["finding_id"]
            for item in self.items.values()
            if not item.get("verified") and item.get("policy_route") in ("runtime", "triage")
        ]
        result["issues"] = list(dict.fromkeys(self.issues))
        result["proposal_ready"] = bool(result["verified_actions"] and not self.issues)
        if self.issues:
            action, reason = "block", "Required push review incomplete"
            result["status"] = "incomplete"
        elif any(h["push_policy"] == "block" for h in self.hits.values()):
            action, reason = (
                "block",
                "Credential match in outgoing history; owner remediation required",
            )
        elif result["proposal_ready"]:
            action, reason = "block", "Verified repair requires a new commit"
        elif pending:
            action, reason = "acknowledge", "P2 warning requires acknowledgement"
        else:
            action, reason = "allow", "Local policy checks satisfied"
        result.update(
            workflow_version=1,
            elapsed_ms=round((time.monotonic() - self.started) * 1000),
            push_decision=dict(action=action, reason=reason, pending=pending),
        )
        history.finish(self.sid, result)
        return {}

    def authorize(self, state):
        scan = history.detail(self.sid)
        if not scan.get("proposal_ready"):
            return {}
        issue = scan.get("staging_issue")
        if self.mode == "vibe-coder":
            self.report("stage")
            try:
                push_stage.apply(self.sid, automatic=True)
                issue = None
            except ERRORS as exc:
                issue = provider.redact(str(exc))
        with history.database() as db:
            pending = scan["push_decision"]["pending"]
            remaining = [
                fid
                for fid in pending
                if not db.execute(
                    "SELECT 1 FROM acknowledgements WHERE repo=? AND snapshot=? AND finding=?",
                    (str(self.repo), scan["snapshot"]["sha256"], fid),
                ).fetchone()
            ]
            if remaining != pending or issue != scan.get("staging_issue"):
                body = json.loads(
                    db.execute("SELECT result FROM scans WHERE id=?", (self.sid,)).fetchone()[0]
                )
                body["push_decision"]["pending"] = remaining
                body["staging_issue"] = issue
                db.execute(
                    "UPDATE scans SET result=? WHERE id=?",
                    (history.encoded(body), self.sid),
                )
                history.event(
                    db,
                    self.sid,
                    "automatic staging deferred" if issue else "receipt updated",
                )
        return {}


def review_push(repo: Path, remote: str, lines: str, *, progress=None):
    with push_stage.repository_lock(repo), tracing_context(enabled=False):
        run = PushReview(repo, remote, lines, progress)
        graph = StateGraph(PushState)
        for name in ("collect", "scan", "review", "aggregate", "authorize"):
            graph.add_node(name, getattr(run, name))
        graph.add_edge(START, "collect")
        graph.add_conditional_edges("collect", lambda s: "authorize" if s["reuse"] else "scan")
        graph.add_edge("scan", "review")
        graph.add_edge("review", "aggregate")
        graph.add_edge("aggregate", "authorize")
        graph.add_edge("authorize", END)
        graph.compile().invoke({"mode": run.mode}, {"recursion_limit": 8})
        return history.detail(run.sid)
