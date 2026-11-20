"""Independent research roles and an arm-blind audit of the resulting candidate."""

import re
import tempfile
import time
from pathlib import Path
from . import checks, owned, pipeline, provider, repair, sandbox
from .snapshot import HEADER, ORIGINAL_HASH
from .workspace import CONTROL, FIXTURE, digest


def patterns(files):
    predicates = {
        "query": r"SELECT.*(\$\{|\+)",
        "secret": r"LMTEST_",
        "guard": r"router\.get\(",
        "dependency": r"node_modules/lodash",
    }
    findings = []
    for path, data in files.items():
        text = data.decode(errors="replace")
        for category, pattern in predicates.items():
            for match in re.finditer(pattern, text):
                findings.append(
                    dict(
                        category=category,
                        path=path,
                        line=text.count("\n", 0, match.start()) + 1,
                        source="pattern",
                    )
                )
    return findings


def suite(path, data):
    if path == "search.js" and digest(data.removeprefix(HEADER)) == ORIGINAL_HASH:
        return "binding"
    return next(
        (
            t
            for t, v in sandbox.OWNED.items()
            if path == v["path"] and data == sandbox.owned_bytes(t, "before")
        ),
        None,
    )


def original_check(test, path, data):
    if test == "binding":
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / path).write_bytes(data)
            (root / CONTROL).write_bytes((FIXTURE / "fixture" / CONTROL).read_bytes())
            before = checks.check(root)
        if (
            before["binding"]["status"] == "fail"
            and before["sqlite"]["status"] == "pass"
            and before["semgrep"].get("negative_control") == "pass"
            and len(before["semgrep"].get("findings", [])) == 1
        ):
            return {
                "property": "parameter binding",
                "status": "fail",
                "observations": before["binding"]["observations"],
            }
        return {"status": "incomplete", "reason": "Original search property not established"}
    return owned.observe(test, data)


def audit(files, candidate):
    if not isinstance(candidate, dict) or not isinstance(candidate.get("path"), str):
        raise ValueError("Invalid edit scope")
    path = candidate["path"]
    data = files.get(path, b"")
    test = suite(path, data)
    if not test:
        raise ValueError("No reviewed adapter for this source")
    if test == "binding":
        line = 3 if data.startswith(HEADER) else 2
        replacement = repair.fix(data, line, candidate)
        return repair.verify(data, replacement, "blind audit", line)
    if set(candidate) != {"path", "source"} or not isinstance(candidate["source"], str):
        raise ValueError("Expected one scoped replacement file")
    return owned.audit(test, data, candidate["source"].encode())


def predictions(response, files):
    values = response.get("findings")
    if not isinstance(values, list) or len(values) > 40:
        raise ValueError("Invalid prediction list")
    for h in values:
        if (
            not isinstance(h, dict)
            or h.get("category") not in provider.CATEGORIES
            or h.get("path") not in files
            or not isinstance(h.get("rationale"), str)
            or not isinstance(h.get("property"), str)
            or (h.get("line") is not None and (type(h["line"]) is not int or h["line"] < 1))
        ):
            raise ValueError("Invalid finding location, category or rationale")
    return values


def independent_call(name, artifact, trace, *, schema=None, **limits):
    """One stateless role invocation, with an optional validated artifact contract."""
    result = provider.role(name, artifact, trace, **limits)
    return schema.model_validate(result) if schema is not None else result


def arm(system, files, safe, *, before_files=None):
    start = time.monotonic()
    trace, findings, issues, audits = [], [], [], []
    result = dict(
        findings=findings,
        role_calls=trace,
        issues=issues,
        audits=audits,
        scope_limits=pipeline.LIMITS,
        proposals=[],
        abstained=False,
        raw_predictions_complete=False,
    )
    try:
        if system == "A":
            findings.extend(patterns(files))
            result["raw_predictions_complete"] = True
        elif system == "template":
            r = pipeline.inspect(
                {"snapshot": {"issues": []}, "baseline_known": before_files is not None,
                 "skip_registry_check": True},
                files,
                before_files=before_files,
            )
            findings.extend(r["findings"])
            issues.extend(r["issues"])
            result["raw_predictions_complete"] = not r["issues"]
            for candidate in r.get("repairs", []):
                if candidate.get("test_id"):
                    edit = {"path": candidate["path"], "source": candidate["candidate"]}
                elif candidate["suite"] == "phase1-binding-v1":
                    edit = {"path": "search.js", "replacement": repair.REPLACEMENT.decode()}
                else:
                    continue
                result["proposals"].append(edit)
        elif system in ("B", "split"):
            artifact = {"schema": 2, "proposed_files": safe}
            if before_files:
                from .snapshot import TOKEN

                artifact["previous_manifests"] = {
                    k: TOKEN.sub("[redacted]", v.decode())
                    for k, v in before_files.items()
                    if k.endswith("package.json")
                }
            response = independent_call("B" if system == "B" else "detect", artifact, trace)
            findings.extend(predictions(response, files))
            result["raw_predictions_complete"] = True
            if system == "B":
                if "candidate" not in response:
                    raise ValueError("Single-call response omitted its candidate decision")
                if response["candidate"] is not None:
                    result["proposals"].append(response["candidate"])
            elif findings:
                # One verification invocation per case. It can abstain; runner owns the catalog.
                options = {
                    p: t
                    for p, b in files.items()
                    if (t := suite(p, b))
                    and any(
                        f["path"] == p
                        and f["category"]
                        == ("query" if t == "binding" else sandbox.OWNED[t]["category"])
                        for f in findings
                    )
                }
                refs = {p: digest(files[p]) for p in options}
                choice = independent_call(
                    "verify",
                    dict(schema=2, candidates=findings, evidence_refs=refs, allowed_tests=options),
                    trace,
                )
                test = choice["test_id"]
                if test is not None:
                    if test not in options.values():
                        raise ValueError("Verifier selected an unsupported test")
                    path = next(p for p in options if options[p] == test)
                    observation = original_check(test, path, files[path])
                    if observation["status"] == "incomplete":
                        raise ValueError("Original property check incomplete")
                    if observation["status"] == "fail":
                        answer = independent_call(
                            "fix",
                            dict(
                                schema=2,
                                property=sandbox.PROPERTIES[test],
                                evidence=observation["observations"],
                                scope={"path": path, "source": safe[path], "sha256": refs[path]},
                            ),
                            trace,
                        )
                        if answer["candidate"] is not None:
                            edit = answer["candidate"]
                            if not isinstance(edit, dict) or edit.get("path") != path:
                                raise ValueError("Fixing role exceeded its authorized edit scope")
                            result["proposals"].append(edit)
            result["abstained"] = not result["proposals"]
        else:
            raise ValueError("Unsupported arm")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        issues.append(str(exc))
    verify_start = time.monotonic()
    for edit in result["proposals"]:
        try:
            r = audit(files, edit)
            if r["verdict"] == "incomplete":
                issues.append(r.get("reason") or "Independent audit incomplete")
            audits.append(
                {
                    k: r.get(k)
                    for k in (
                        "path",
                        "verdict",
                        "property",
                        "suite_digest",
                        "original_sha256",
                        "candidate_sha256",
                        "before",
                        "after",
                        "reason",
                    )
                }
            )
        except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
            audits.append(dict(verdict="unsupported", reason=str(exc)))
    result.update(
        status="incomplete" if issues else "findings" if findings else "clean",
        verification_ms=round((time.monotonic() - verify_start) * 1000, 3),
        model_ms=sum(c["duration_ms"] for c in trace),
        elapsed_ms=round((time.monotonic() - start) * 1000, 3),
    )
    return result
