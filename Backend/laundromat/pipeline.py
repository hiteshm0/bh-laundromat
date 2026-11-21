"""The deterministic scan controller combines static evidence with the one supported verifier."""

import subprocess
import time
from importlib.metadata import version
from pathlib import Path

from . import detect, repair, owned, sandbox, history, llm_review, manifests
from .snapshot import ORIGINAL_HASH, HEADER, TOKEN
from .workspace import digest

ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired)


LIMITS = [
    "Encoded credentials are outside literal secret rules.",
    "Cross-module data flow and business-logic correctness are outside the measured properties.",
]


def scan_rules(request, files, *, before_files=None, context_files=None):
    hits, coverage, signals = [], {}, []
    issues = list(request["snapshot"]["issues"])
    if request.get("task_status", "completed") != "completed":
        issues.append(request["task_status"])
    result = dict(
        findings=hits,
        scope_limits=LIMITS,
        structural_observations=[],
        verified_actions=[],
        coverage=coverage,
        issues=issues,
        dependency_changes=signals,
        push_decision={
            "action": "not evaluated",
            "reason": "Snapshot review; outgoing history is evaluated at push.",
        },
        versions={
            "semgrep": version("semgrep"),
            "rules": {
                p.name: digest(p.read_bytes()) for p in detect.RULES.iterdir() if p.is_file()
            },
        },
    )
    for kind in (
        "secret",
        "query",
        "guard",
        "dependency",
        "package metadata",
        "manifest",
        "argument and role boundaries",
    ):
        coverage[kind] = {"status": "outside scope", "paths": []}

    selected = request.get("category")
    families = {
        "secret": {"secret"},
        "query": {"query", "injection"},
        "guard": {"guard"},
        "dependency": {"dependency"},
        "package metadata": {"dependency", "supply-chain"},
        "manifest": {"supply-chain", "slopsquatting"},
        "argument and role boundaries": {"command", "prompt", "injection"},
    }

    def run(kind, paths, operation):
        if selected and selected not in families[kind]:
            return
        check = coverage[kind]
        check["paths"].extend(paths)
        started = time.monotonic()
        try:
            operation()
            if check["status"] != "incomplete":
                check["status"] = "complete"
        except ERRORS as exc:
            check["status"] = "incomplete"
            if kind == "secret":
                check.setdefault("failed_paths", []).extend(paths)
            issues.append(f"{kind}: {exc}")
        finally:
            check["duration_ms"] = check.get("duration_ms", 0) + round(
                (time.monotonic() - started) * 1000
            )

    def secret(name, data):
        if b"\0" in data:
            raise ValueError(f"{name} binary content outside text coverage")
        hits.extend(detect.secrets(data, name))

    if files and selected in (None, "secret"):
        try:
            result["versions"]["gitleaks"] = (
                subprocess.check_output(
                    ["gitleaks", "version"], timeout=5, stderr=subprocess.DEVNULL
                )
                .decode()
                .strip()
            )
        except (OSError, subprocess.SubprocessError):
            result["versions"]["gitleaks"] = "unavailable"
    for name, data in files.items():
        if not request.get("skip_history_secrets"):
            run("secret", [name], lambda: secret(name, data))
        leaf = Path(name).name
        if leaf == "package.json":

            def manifest():
                before = (before_files or {}).get(name)
                previous = before or b"{}"
                additions = detect.manifest_additions(previous, data)
                if selected in (None, "slopsquatting") and not request.get("skip_registry_check"):
                    hits.extend(manifests.hallucinated_packages(name, additions))
                if before is None and not request.get("baseline_known"):
                    # Existence can be checked for a standalone manifest. Claims
                    # about newly added dependencies still require a baseline.
                    if additions and selected != "slopsquatting":
                        raise ValueError(f"{name}: previous declarations unknown")
                    return
                if selected in (None, "slopsquatting"):
                    hits.extend(detect.similar_names(name, additions))
                if selected == "slopsquatting":
                    return
                import json

                scripts_old = json.loads(previous).get("scripts", {})
                scripts_new = json.loads(data).get("scripts", {})
                if scripts_old != scripts_new:
                    result.setdefault("parent_script_changes", []).append(
                        dict(
                            path=name,
                            changed=sorted(
                                n
                                for n in scripts_new.keys() | scripts_old.keys()
                                if scripts_old.get(n) != scripts_new.get(n)
                            ),
                        )
                    )
                found, observations = detect.dependency_structure(
                    name,
                    previous,
                    context_files or files,
                    complete=request.get("full_context", True)
                    and not request["snapshot"]["issues"],
                )
                hits.extend(found)
                result["structural_observations"].extend(observations)
                unknown = [
                    o["package"] + ": " + o["reason"]
                    for o in observations
                    if o["status"] == "unknown"
                ]
                if unknown:
                    raise ValueError(", ".join(unknown))

            run("manifest", [name], manifest)
        if leaf == "routes.js":

            def routes():
                found, observed, problems = detect.guards(data, name)
                hits.extend(found)
                coverage["guard"].setdefault("routes", []).extend(observed)
                if problems:
                    raise ValueError(", ".join(problems))

            run("guard", [name], routes)
        if leaf == "package-lock.json":
            run("dependency", [name], lambda: hits.extend(detect.dependencies(data, name)))
        elif leaf in (
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "Cargo.lock",
            "bun.lock",
            "bun.lockb",
        ) and selected in (None, "dependency"):
            coverage["dependency"]["status"] = "incomplete"
            issues.append(f"Unsupported lockfile: {name}")
        if leaf == "recorded-package.json":
            run("package metadata", [name], lambda: signals.append(dict(detect.install_change(data), path=name)))
    js = {name: data for name, data in files.items() if name.endswith((".js", ".cjs", ".mjs"))}
    for path, data in js.items():
        run(
            "argument and role boundaries",
            [path],
            lambda: hits.extend(detect.boundaries(data, path)),
        )
    if js:

        def query_scan():
            found, actual_version = detect.queries(js)
            result["versions"]["semgrep"] = actual_version
            hits.extend(found)

        run("query", list(js), query_scan)
    if (
        coverage["query"]["status"] == "incomplete"
        and digest(files.get("search.js", b"").removeprefix(HEADER)) == ORIGINAL_HASH
    ):
        hits.append(
            detect.finding(
                "query",
                "fixture.static-expression",
                "search.js",
                None,
                "P3",
                "reviewed fixture identity",
                "Known expression present. Scanner unavailable.",
            )
        )
    if selected in ("command", "prompt"):
        hits[:] = [h for h in hits if h["category"] == selected]
    hits.sort(key=lambda h: (h["severity"], h["path"], h["line"] or 0, h["rule"]))
    return result


def inspect(
    request,
    files,
    *,
    model_only=False,
    model_context=None,
    before_files=None,
    context_files=None,
    verify=True,
    progress_callback=None,
    phase_callback=None,
):
    result = scan_rules(request, files, before_files=before_files, context_files=context_files)
    hits, coverage, issues = result["findings"], result["coverage"], result["issues"]
    selected = request.get("category")
    if hits and phase_callback:
        phase_callback("Reviewing findings…")
    for hit in hits:
        if progress_callback:
            severity = "Critical" if hit["severity"] == "P1" else hit["severity"]
            progress_callback(TOKEN.sub("[redacted]", f"[detect] {severity}  {hit['category']}  "
                                        f"{hit['path']}:{hit['line'] or '—'}  {hit['explanation'][:80]}"))
        hit["state"] = "candidate"
        if request.get("progress_id"):
            history.progress(request["progress_id"], hit)
        if not verify:
            continue
        for test, item in sandbox.OWNED.items():
            path = hit["path"]
            if (
                path == item["path"]
                and hit["category"] == item["category"]
                and files[path] == sandbox.owned_bytes(test, "before")
            ):
                observation = owned.observe(test, files[path], progress_callback)
                if progress_callback:
                    progress_callback(f"[sandbox] BEFORE {test}: {observation['status'].upper()}")
                hit["original_observations"] = observation
                if observation["status"] == "fail":
                    candidate = owned.audit(
                        test, files[path], sandbox.owned_bytes(test, "after"), observation, progress_callback
                    )
                    candidate["finding_id"] = hit["id"]
                    result.setdefault("repairs", []).append(candidate)
                    if result.get("repair", {}).get("verdict", "candidate") == "candidate":
                        result["repair"] = candidate
                    hit["candidate_observations"] = candidate["after"]
                    hit["repair_status"] = candidate["verdict"] + " " + item["property"]
                    if candidate["verdict"] == "verified":
                        hit.update(state="property-confirmed", property=item["property"])
                    else:
                        issues.append(candidate["reason"])
                elif observation["status"] == "incomplete":
                    issues.append(observation["reason"])
        if hit["category"] == "secret" and "candidate_observations" not in hit:
            if phase_callback:
                phase_callback("Preparing a repair suggestion…")
            candidate = repair.propose_secret_repair(files[hit["path"]], hit)
            if candidate:
                result.setdefault("repairs", []).append(candidate)
                result.setdefault("repair", candidate)
                hit["repair_status"] = "candidate env-var substitution"
                if request.get("progress_id"):
                    history.progress(request["progress_id"], hit)
        if hit["category"] != "query":
            continue
        hit["repair_status"] = "unsupported query style or path"
        if hit["rule"] == "laundromat.interpolated-search" and hit["path"] == "search.js":
            try:
                candidate = repair.propose(
                    files["search.js"],
                    hit,
                    request.get("model", False),
                    fallback=not model_only,
                    model_context=model_context,
                    progress_callback=progress_callback,
                )
                if candidate:
                    result["repair"] = candidate
                    candidate["finding_id"] = hit["id"]
                    result.setdefault("repairs", []).append(candidate)
                    hit["candidate_observations"] = candidate["after"]
                    if candidate["verdict"] == "verified":
                        hit.update(state="property-confirmed", property=candidate["property"])
                    if candidate["verdict"] == "verified" and "task_finished" in request:
                        result["task_to_verified_patch_ms"] = round(
                            (time.time() - request["task_finished"]) * 1000
                        )
                    if candidate["verdict"] == "incomplete":
                        issues.append(candidate["reason"])
            except ERRORS as exc:
                hit["repair_status"] = "verification incomplete"
                issues.append(f"parameter binding: {exc}")
    for hit in hits:
        hit["scope_limits"] = LIMITS
        if request.get("progress_id") and hit["state"] != "candidate":
            history.progress(request["progress_id"], hit)
        if hit.get("original_observations") and "incomplete" in hit["repair_status"]:
            issues.append("Original fixture check did not establish the required property")
    result["raw_candidates"] = [
        {k: h[k] for k in ("id", "path", "rule", "category", "line", "severity", "source")}
        for h in hits
    ]
    result["unsupported_checks"] = [h["id"] for h in hits if h["state"] != "property-confirmed"]
    result["unsupported_checks"] += [k for k, c in coverage.items() if c["status"] == "incomplete"]
    if not issues:
        result["verified_actions"] = [
            {
                "finding_id": r["finding_id"],
                "property": r["property"],
                "path": r["path"],
                "sha256": r["candidate_sha256"],
            }
            for r in result.get("repairs", [])
            if r["verdict"] == "verified"
        ]
    if selected and all(v["status"] == "outside scope" for v in coverage.values()):
        issues.append("No supported inputs for selected class " + selected)
        result["verified_actions"] = []
    issues[:] = [TOKEN.sub("[redacted]", str(reason)) for reason in issues]
    result["status"] = "incomplete" if issues else "findings" if hits else "clean"
    if request.get("advisory_review"):
        result["llm_review"] = llm_review.inspect_snapshot(
            request["snapshot"], files, result, phase_callback
        )
    return result
