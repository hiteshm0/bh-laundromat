"""Evaluate the frozen v2 corpus. The original experiment is available in evaluate_v1.py."""

import argparse
import json
import os
import platform
import random
import subprocess
from pathlib import Path
from collections import defaultdict
from importlib.metadata import version

from laundromat import experiment, provider
from laundromat.snapshot import TOKEN
from laundromat.workspace import digest

try:
    from .evaluate_v1 import materialize as materialize_v1
except ImportError:
    from evaluate_v1 import materialize as materialize_v1

HERE = Path(__file__).resolve().parent
CLASSES = provider.CATEGORIES


def materialize(case):
    files, safe = materialize_v1(case)
    for path, content in files.items():
        files[path] = content.replace(b"{{CONFIG_VALUE}}", b"LMTEST_" + b"Q" * 24)
        safe[path] = TOKEN.sub("[redacted]", safe[path]).replace(
            "{{CONFIG_VALUE}}", "[redacted literal synthetic credential]"
        )
        for i in range(2):
            if "{{ENCODED_" + str(i) + "}}" in case["files"][path]:
                safe[path] = safe[path].replace(
                    "[redacted synthetic value]", "[redacted encoded synthetic value]"
                )
    return files, safe


def measured(case, system, rep):
    files, safe = materialize(case)
    r = experiment.arm(
        system,
        files,
        safe,
        before_files={p: v.encode() for p, v in case.get("before_files", {}).items()},
    )
    predicted = sorted({h["category"] for h in r["findings"]})
    confirmed = [a for a in r["audits"] if a["verdict"] == "verified"]
    return dict(
        case=case["id"],
        group=case["group"],
        system=system,
        repetition=rep,
        eligible=case["eligible"],
        labels=case["labels"],
        predicted=predicted,
        unexpected=sorted(set(predicted) - set(case["labels"])),
        proposals=len(r["proposals"]),
        proposal_classes=[
            next(
                (
                    h["category"]
                    for h in r["findings"]
                    if isinstance(p, dict) and h.get("path") == p.get("path")
                ),
                None,
            )
            for p in r["proposals"]
        ],
        raw_predictions_complete=r["raw_predictions_complete"],
        verified=len(confirmed),
        confirmed_classes=[
            {
                "parameter binding": "query",
                **{v["property"]: v["category"] for v in experiment.sandbox.OWNED.values()},
            }[a["property"]]
            for a in confirmed
        ],
        regressions=sum(
            a.get("after", {}).get("sqlite", {}).get("status") == "fail"
            or (a.get("after", {}).get("observations") or {}).get("regression") is False
            for a in r["audits"]
            if isinstance(a.get("after"), dict)
        ),
        **{
            k: r[k]
            for k in (
                "status",
                "issues",
                "role_calls",
                "findings",
                "audits",
                "model_ms",
                "verification_ms",
                "elapsed_ms",
                "abstained",
            )
        },
    )


def ratio(a, b):
    return a / b if b else None


def score(rows, classes):
    complete = [r for r in rows if r["raw_predictions_complete"]]
    matrix = dict(TP=0, FP=0, TN=0, FN=0)
    after_tp = 0
    for row in complete:
        for c in classes:
            actual, pred = c in row["labels"], c in row["predicted"]
            matrix[("T" if actual == pred else "F") + ("P" if pred else "N")] += 1
            after_tp += actual and c in row["confirmed_classes"]
    tp, fp, tn, fn = (matrix[k] for k in ("TP", "FP", "TN", "FN"))
    uncertain = sum(
        len(set(r["labels"]) & set(classes)) for r in rows if not r["raw_predictions_complete"]
    )
    eligible = sum(r["eligible"] and bool(set(r["labels"]) & set(classes)) for r in rows)
    verified = sum(sum(c in classes for c in r["confirmed_classes"]) for r in rows)
    proposals = sum(
        r["proposals"]
        if len(classes) == len(CLASSES)
        else sum(c in classes for c in r["proposal_classes"])
        for r in rows
    )
    tokens = [
        c["usage"].get("total_tokens") for r in rows for c in r["role_calls"] if c.get("usage")
    ]
    return dict(
        **matrix,
        nominal=len(rows),
        completed=len(complete),
        incomplete=len(rows) - len(complete),
        workflow_incomplete=sum(r["status"] == "incomplete" for r in rows),
        precision=ratio(tp, tp + fp),
        recall=ratio(tp, tp + fn),
        FPR=ratio(fp, tn + fp),
        after_recall=ratio(after_tp, tp + fn),
        true_positive_bounds=[tp, tp + uncertain],
        proposed=proposals,
        verified=verified,
        eligible=eligible,
        verified_per_proposal=ratio(verified, proposals),
        verified_per_eligible=ratio(
            sum(c in classes for r in rows if r["eligible"] for c in r["confirmed_classes"]),
            eligible,
        ),
        regressions=sum(r["regressions"] for r in rows),
        model_ms=sum(r["model_ms"] for r in rows),
        verification_ms=sum(r["verification_ms"] for r in rows),
        elapsed_ms=sum(r["elapsed_ms"] for r in rows),
        total_tokens=sum(v for v in tokens if v is not None) if tokens else None,
        cost_usd=0 if not any(r["role_calls"] for r in rows) else None,
    )


def interval(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[r["group"]].append(r)
    rng = random.Random(203)
    values = []
    for _ in range(500):
        sample = [r for g in rng.choices(sorted(groups), k=len(groups)) for r in groups[g]]
        val = score(sample, CLASSES)["recall"]
        if val is not None:
            values.append(val)
    if not values:
        return None
    values.sort()
    return [values[int(len(values) * q)] for q in (0.025, 0.975)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--arm", choices=("A", "B", "split", "template"))
    parser.add_argument("--case")
    parser.add_argument("--group")
    args = parser.parse_args()
    if args.arm in ("B", "split") and not args.live:
        parser.error("Model arms require --live")
    for v in (1, 2):
        raw = (HERE / f"manifest-v{v}.json").read_bytes()
        fingerprint = digest(raw)
        if fingerprint != (HERE / f"manifest-v{v}.sha256").read_text().split()[0]:
            parser.error("Frozen corpus digest mismatch")
    cases = [
        c
        for c in json.loads(raw)["cases"]
        if c["split"] == "held-out"
        and (not args.case or args.case == c["id"])
        and (not args.group or args.group == c["group"])
    ]
    if not cases:
        parser.error("No held-out cases match")
    systems = [args.arm] if args.arm else ["A", "template"] + (["B", "split"] if args.live else [])
    out = args.out or HERE / ("results-live-v2.json" if args.live else "results-offline-v2.json")
    rows = []
    metrics = {}
    spread = {}
    pinned_revision = None
    for system in systems:
        for rep in range(1, 4 if system in ("B", "split") else 2):
            batch = [measured(case, system, rep) for case in cases]
            for row in batch:
                revisions = [c["model"] for c in row["role_calls"] if c.get("model")]
                if revisions:
                    pinned_revision = pinned_revision or revisions[0]
                    if any(revision != pinned_revision for revision in revisions):
                        row.update(status="incomplete", raw_predictions_complete=False)
                        row["issues"].append(
                            "Returned provider revision changed during the frozen run"
                        )
            rows.extend(batch)
            metrics[f"{system}/{rep}"] = {c: score(batch, [c]) for c in CLASSES}
            metrics[f"{system}/{rep}"]["by_group"] = {
                g: score([r for r in batch if r["group"] == g], CLASSES)
                for g in sorted({r["group"] for r in batch})
            }
            metrics[f"{system}/{rep}"]["all"] = dict(
                **score(batch, CLASSES), group_bootstrap_recall_95=interval(batch)
            )
        spread[system] = {
            k: [min(vals), max(vals)] if vals else None
            for k in ("recall", "precision", "verified_per_eligible", "model_ms")
            for vals in [
                [
                    v["all"][k]
                    for n, v in metrics.items()
                    if n.startswith(system + "/") and v["all"][k] is not None
                ]
            ]
        }
    pending = [
        s
        for s in ("B", "split")
        if s not in systems or any(r["status"] == "incomplete" for r in rows if r["system"] == s)
    ]
    result = dict(
        manifest_sha256=fingerprint,
        held_out=len(cases),
        metrics=metrics,
        rows=rows,
        pending=pending,
        spread=spread,
        model=os.getenv("LAUNDROMAT_MODEL"),
        returned_model_revision=pinned_revision,
        roles=provider.ROLES,
        prompt_character_budgets=provider.PROMPT_LIMITS,
        output_token_budgets=provider.OUTPUT_LIMITS,
        settings=dict(store=False, tools=[], sampling="provider default"),
        runtime=os.getenv("LAUNDROMAT_RUNTIME", "strict"),
        environment=dict(
            python=platform.python_version(),
            semgrep=version("semgrep"),
            gitleaks=subprocess.getoutput("gitleaks version"),
            node=subprocess.getoutput("node --version"),
        ),
        failures=[
            dict(
                case=r["case"],
                system=r["system"],
                missing=sorted(set(r["labels"]) - set(r["predicted"])),
                extra=r["unexpected"],
                issues=r["issues"],
            )
            for r in rows
            if r["issues"] or set(r["labels"]) != set(r["predicted"])
        ],
    )
    out.write_text(json.dumps(result, indent=2) + "\n")
    table = [
        "# Held-out v2 measurements",
        "",
        "|Arm / run|Completed / nominal|TP|FP|TN|FN|Precision|Recall|Verified / proposed|Eligible|",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, sets in metrics.items():
        v = sets["all"]
        table.append(
            f"|{name}|{v['completed']}/{v['nominal']}|{v['TP']}|{v['FP']}|{v['TN']}|{v['FN']}|"
            + "|".join("—" if v[k] is None else f"{v[k]:.3f}" for k in ("precision", "recall"))
            + f"|{v['verified']}/{v['proposed']}|{v['eligible']}|"
        )
    table += ["", "Pending or incomplete live arms · " + ", ".join(pending)] if pending else []
    out.with_suffix(".md").write_text("\n".join(table) + "\n")
    print("\n".join(table))


if __name__ == "__main__":
    main()
