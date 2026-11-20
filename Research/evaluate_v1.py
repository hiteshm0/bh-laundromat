"""Reproduce the frozen per-change comparison. No provider calls unless --live is supplied."""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import time
from importlib.metadata import version
from pathlib import Path

from laundromat import pipeline, provider, repair
from laundromat.snapshot import ORIGINAL_HASH, HEADER
from laundromat.workspace import digest

HERE = Path(__file__).resolve().parent
CLASSES = ["query", "secret", "guard", "dependency"]


def materialize(case):
    raw = dict(case["files"])
    safe = {}
    for file, text in raw.items():
        redacted = text
        for i in range(2):
            token = (
                "LMTEST_" + hashlib.sha256(f"inert fixture {i}".encode()).hexdigest()[:24].upper()
            )
            for key, value in [
                (f"{{{{TEST_TOKEN_{i}}}}}", token),
                (f"{{{{ENCODED_{i}}}}}", base64.b64encode(token.encode()).decode()),
            ]:
                text = text.replace(key, value)
                redacted = redacted.replace(key, "[redacted synthetic value]")
        raw[file] = text.encode()
        safe[file] = redacted
    return raw, safe


def baseline(files):
    text = "\n".join(v.decode() for v in files.values())
    predicates = {
        "query": r"SELECT.*(\$\{|\+)",
        "secret": r"LMTEST_",
        "guard": r"router\.get\(",
        "dependency": r"node_modules/lodash",
    }
    return [k for k, v in predicates.items() if re.search(v, text)]


def measured(case, system, repetition):
    files, safe = materialize(case)
    start = time.perf_counter()
    categories, proposed, verified, regression, tokens, issue = [], False, False, False, None, None
    patch_ms = None
    model_version = None
    repair_issue = None
    evidence = {}
    try:
        if system == "A":
            categories = baseline(files)
        elif system == "B":
            answer = provider.ask(safe, "B")
            categories, tokens, model_version = (
                answer["categories"],
                answer["usage"],
                answer["model"],
            )
            proposed = answer["candidate"] is not None
            data = files.get("search.js", b"")
            if proposed and digest(data.removeprefix(HEADER)) == ORIGINAL_HASH:
                line = 3 if data.startswith(HEADER) else 2
                try:
                    candidate = repair.fix(data, line, answer["candidate"])
                    r = repair.verify(data, candidate, "model", line)
                    verified = r["verdict"] == "verified"
                    regression = r["after"]["sqlite"]["status"] == "fail"
                    if r["verdict"] == "incomplete":
                        issue = r["reason"]
                except (ValueError, TypeError, AttributeError):
                    repair_issue = "Candidate failed the fixed shape check"
            elif proposed:
                repair_issue = "Candidate proposed outside supported fixture"
        else:
            # C uses the same detection/controller/verifier as the CLI. Pass the exact
            # fixture slice to the model; non-search classes have no supported repair.
            result = pipeline.inspect(
                {"snapshot": {"issues": []}, "model": system == "C"},
                files,
                model_only=system == "C",
                model_context=safe,
            )
            categories = [h["category"] for h in result["findings"]]
            evidence = {
                "matches": [
                    {"rule": h["rule"], "repair_status": h["repair_status"]}
                    for h in result["findings"]
                ],
                "recorded_changes": result.get("dependency_changes", []),
            }
            for hit in result["findings"]:
                if attempt := hit.get("model_attempt"):
                    proposed, tokens, model_version = (
                        attempt["proposed"],
                        attempt["usage"],
                        attempt["model"],
                    )
                    repair_issue = attempt.get("reason")
            if result["issues"]:
                issue = " | ".join(result["issues"])
            if r := result.get("repair"):
                proposed, verified = True, r["verdict"] == "verified"
                regression = r["after"]["sqlite"]["status"] == "fail"
                tokens, model_version = r.get("usage"), r.get("model")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        issue = str(exc)
    ms = round((time.perf_counter() - start) * 1000, 5)
    if verified:
        patch_ms = ms
    return dict(
        case=case["id"],
        category=case["category"],
        positive=case["positive"],
        eligible=case["eligible"],
        system=system,
        repetition=repetition,
        predicted=case["category"] in categories,
        proposed=proposed,
        verified=verified,
        regression=regression,
        issue=issue,
        elapsed_ms=ms,
        verified_patch_ms=patch_ms,
        usage=tokens,
        model_version=model_version,
        repair_issue=repair_issue,
        evidence=evidence,
    )


def ratio(n, d):
    return n / d if d else None


def score(rows, system):
    complete = [r for r in rows if not r["issue"]]
    tp = sum(r["positive"] and r["predicted"] for r in complete)
    fp = sum(not r["positive"] and r["predicted"] for r in complete)
    fn = sum(r["positive"] and not r["predicted"] for r in complete)
    tn = len(complete) - tp - fp - fn
    eligible = [r for r in rows if r["eligible"]]
    verified = sum(r["verified"] for r in rows)
    proposals = sum(r["proposed"] for r in rows)
    query = [r for r in complete if r["category"] == "query" and r["positive"]]
    usage = [r["usage"] for r in rows if r["usage"]]
    return dict(
        n=len(rows),
        incomplete=len(rows) - len(complete),
        TP=tp,
        FP=fp,
        TN=tn,
        FN=fn,
        precision=ratio(tp, tp + fp),
        recall=ratio(tp, tp + fn),
        false_positive_rate=ratio(fp, fp + tn),
        proposed=proposals,
        eligible=len(eligible),
        verified=verified,
        fix_per_proposal=ratio(verified, proposals),
        fix_per_eligible=ratio(sum(r["verified"] for r in eligible), len(eligible))
        if system != "A"
        else None,
        regressions=sum(r["regression"] for r in rows),
        repair_issues=sum(bool(r["repair_issue"]) for r in rows),
        ms=sum(r["elapsed_ms"] for r in rows),
        query_recall_before=ratio(sum(r["predicted"] for r in query), len(query)),
        query_recall_after=ratio(sum(r["verified"] for r in query), len(query))
        if system != "A"
        else None,
        total_tokens=sum(u["total_tokens"] for u in usage) if usage else None,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    args.out = args.out or HERE / ("results-live.json" if args.live else "results-offline.json")
    if args.live and not (os.getenv("OPENAI_API_KEY") and os.getenv("LAUNDROMAT_MODEL")):
        parser.error("Live B/C pending: set OPENAI_API_KEY and LAUNDROMAT_MODEL")
    data = (HERE / "manifest-v1.json").read_bytes()
    fingerprint = digest(data)
    if fingerprint != (HERE / "manifest-v1.sha256").read_text().split()[0]:
        raise ValueError("Frozen manifest hash mismatch")
    cases = [c for c in json.loads(data)["cases"] if c["split"] == "held-out"]
    systems = {"A": 1, "template": 1}
    if args.live:
        systems.update(B=3, C=3)
    rows = [measured(c, s, rep + 1) for s, n in systems.items() for rep in range(n) for c in cases]
    metrics = {}
    for s, n in systems.items():
        for rep in range(1, n + 1):
            selection = [r for r in rows if r["system"] == s and r["repetition"] == rep]
            metrics[f"{s}/{rep}"] = {
                cat: score([r for r in selection if cat == "all" or r["category"] == cat], s)
                for cat in [*CLASSES, "all"]
            }
    spread = {}
    for system in ("B", "C"):
        if system in systems:
            spread[system] = {}
            for metric in ("precision", "recall", "fix_per_eligible", "ms", "total_tokens"):
                vals = [
                    v["all"][metric]
                    for k, v in metrics.items()
                    if k.startswith(system + "/") and v["all"][metric] is not None
                ]
                spread[system][metric] = [min(vals), max(vals)] if vals else None
    result = dict(
        manifest_sha256=fingerprint,
        held_out=len(cases),
        unit="one change evaluated for its nominated class",
        pending=[] if args.live else ["B and C live measurements"],
        configured_model=os.getenv("LAUNDROMAT_MODEL"),
        prompts=provider.PROMPTS,
        contract=provider.CONTRACT,
        policy=provider.POLICY,
        total_prompt_character_limit=provider.BUDGET,
        parameters={"max_output_tokens": 700, "store": False},
        repetitions=systems,
        spread=spread,
        metrics=metrics,
        rows=rows,
        environment={
            "python": platform.python_version(),
            "semgrep": version("semgrep"),
            "gitleaks": subprocess.check_output(["gitleaks", "version"], text=True).strip(),
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        },
    )
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    table = [
        "# Held-out results",
        "",
        "|System/run|Class|N|TP|FP|TN|FN|Precision|Recall|FPR|Verified/proposed|Verified/eligible|Incomplete|",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for system, data in metrics.items():
        for category, v in data.items():

            def fmt(k):
                return "—" if v[k] is None else f"{v[k]:.3f}"

            table.append(
                "|"
                + "|".join(
                    map(
                        str,
                        [
                            system,
                            category,
                            v["n"],
                            v["TP"],
                            v["FP"],
                            v["TN"],
                            v["FN"],
                            fmt("precision"),
                            fmt("recall"),
                            fmt("false_positive_rate"),
                            fmt("fix_per_proposal"),
                            fmt("fix_per_eligible"),
                            v["incomplete"],
                        ],
                    )
                )
                + "|"
            )
    if result["pending"]:
        table += ["", "Live B and C measurements are pending provider credentials."]
    args.out.with_suffix(".md").write_text("\n".join(table) + "\n")
    print("\n".join(table))


if __name__ == "__main__":
    import sys
    import tempfile
    import zipfile

    archive=HERE/"frozen-v1.zip"
    if digest(archive.read_bytes())!="78165b7f8ea55d8306e0c01c1637f7f9e2db9fe139502184ab09e886fc7c36e5":
        raise SystemExit("Frozen v1 source archive digest mismatch")
    argv=sys.argv[1:]
    if "--out" not in argv:
        argv.extend(["--out",str(HERE/"results-v1-reproduced.json")])
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(root)
        env=dict(os.environ,PYTHONPATH=str(root/"Backend"))
        raise SystemExit(subprocess.run([sys.executable,root/"Research/evaluate.py",*argv],env=env).returncode)
