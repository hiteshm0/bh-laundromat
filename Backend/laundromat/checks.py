import json
import os
import ssl
import subprocess
from pathlib import Path

from .workspace import CONTROL, FIXTURE, ROOT, SEARCH, SOURCES, digest

RULE = ROOT / "Backend" / "rules" / "interpolated-search.yml"
RULE_ID = "laundromat.interpolated-search"


def run_json(argv, cwd, env=None):
    result = subprocess.run(
        argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=30, check=False
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValueError(f"{argv[0]} exited {result.returncode}: {detail[:2000]}")
    return json.loads(result.stdout)


CHECK_ERRORS = (OSError, subprocess.TimeoutExpired, ValueError, KeyError, IndexError, TypeError)


def status(ok):
    return "pass" if ok else "fail"


def scan(source: Path):
    env = os.environ.copy()
    env.update(
        SEMGREP_SETTINGS_FILE=str(source.parent / "semgrep-settings.yml"),
        SEMGREP_LOG_FILE=str(source.parent / "semgrep.log"),
    )
    # The native scanner initializes TLS even with a local rule and metrics disabled.
    cafile = ssl.get_default_verify_paths().cafile
    if cafile:
        env.setdefault("SSL_CERT_FILE", cafile)
    argv = [
        "semgrep", "scan", "--config", str(RULE), "--metrics=off", "--disable-version-check",
        "--strict", "--no-git-ignore", "--no-rewrite-rule-ids", "--jobs", "1", "--json", *SOURCES,
    ]
    try:
        report = run_json(argv, source, env)
        if report["errors"] or report.get("skipped_rules"):
            raise ValueError(f"Semgrep errors or skipped rules: {report['errors']} {report.get('skipped_rules')}")
        scanned = sorted(report["paths"]["scanned"])
        if scanned != sorted(SOURCES):
            raise ValueError(f"Semgrep scanned {scanned}, expected {sorted(SOURCES)}")
        hashes = {name: digest((source / name).read_bytes()) for name in scanned}
        findings = [
            {
                "file": hit["path"], "line": hit["start"]["line"], "rule_id": hit["check_id"],
                "message": hit["extra"]["message"], "scanned_sha256": hashes[hit["path"]],
            }
            for hit in report["results"]
        ]
        return {
            "status": "complete", "version": report["version"], "scanned": hashes,
            "findings": findings,
            "negative_control": status(all(hit["file"] != CONTROL for hit in findings)),
        }
    except CHECK_ERRORS as exc:
        return {"status": "incomplete", "reason": str(exc)}


def observations(source, mode):
    return run_json(["node", str(FIXTURE / "observe.cjs"), mode, str(source / SEARCH)], source)


def binding(source, cases):
    try:
        rows = observations(source, "binding")
        expected = [case["term"] for case in cases if case["ids"]]
        if [row["term"] for row in rows] != expected:
            raise ValueError("The adapter observer did not return the expected terms.")
        single = all(len(row["statements"]) == 1 for row in rows)
        constant = single and len({row["statements"][0]["sql"] for row in rows}) == 1
        bound = single and all(
            row["statements"][0]["executions"] == [[row["term"]]] for row in rows
        )
        return {
            "status": status(constant and bound), "constant_sql": constant,
            "bound_arguments": bound, "observations": rows,
        }
    except CHECK_ERRORS as exc:
        return {"status": "incomplete", "reason": str(exc)}


def behavior(source, cases):
    try:
        rows = observations(source, "sqlite")
        if [row["term"] for row in rows] != [case["term"] for case in cases]:
            raise ValueError("SQLite did not return observations for every expected term.")
        results = [
            {"term": case["term"], "expected": case["ids"], "actual": row["ids"],
             "status": status(row["ids"] == case["ids"])}
            for case, row in zip(cases, rows)
        ]
        return {"status": status(all(r["status"] == "pass" for r in results)), "results": results}
    except CHECK_ERRORS as exc:
        return {"status": "incomplete", "reason": str(exc)}


def check(source):
    cases = json.loads((FIXTURE / "cases.json").read_text())
    return {"semgrep": scan(source), "binding": binding(source, cases), "sqlite": behavior(source, cases)}
