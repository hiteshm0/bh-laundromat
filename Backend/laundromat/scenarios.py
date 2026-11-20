"""Positive and independent controls for the six offline review scenarios."""

import json
import tempfile
from pathlib import Path
from . import pipeline, sandbox
from .workspace import FIXTURE, json_bytes
from .snapshot import snapshot

SCENARIOS = ("secret", "injection", "guard", "dependency", "supply-chain", "slopsquatting")


def examples(scenario):
    if scenario not in SCENARIOS:
        raise ValueError("Unknown scenario")
    if scenario in ("injection", "secret", "guard", "dependency"):
        if scenario == "injection":
            for label, filename in (
                ("SQL binding", "search.js"),
                ("bound control", "safe-search.js"),
            ):
                yield label, {}, {"search.js": (FIXTURE / "fixture" / filename).read_bytes()}
        for test in {
            "injection": ["argv", "roles"],
            "secret": ["configuration"],
            "guard": ["access"],
            "dependency": ["advisory"],
        }[scenario]:
            for phase in ("before", "after"):
                yield (
                    test + " " + phase,
                    {},
                    {sandbox.OWNED[test]["path"]: sandbox.owned_bytes(test, phase)},
                )
        if scenario == "secret":
            for prefix, size in (("ghp_", 36), ("github_pat_", 55), ("sk-proj-", 40), ("AKIA", 16)):
                for label, n in (("literal", size), ("short look-alike", 3)):
                    yield prefix + label, {}, {"settings.txt": (prefix + "A" * n + "\n").encode()}
        if scenario == "guard":
            yield (
                "recorded routes",
                {},
                {"routes.js": (FIXTURE / "recorded/routes.js").read_bytes()},
            )
            yield "unknown route", {}, {"routes.js": b'router.get("/unlisted", show);\n'}
        if scenario == "dependency":
            yield (
                "recorded advisory",
                {},
                {"package-lock.json": (FIXTURE / "recorded/package-lock.json").read_bytes()},
            )
        return
    root = FIXTURE / "supply-chain"
    old = {"package.json": (root / "before.json").read_bytes()}
    if scenario == "slopsquatting":
        for name in (
            "expres",
            "experss",
            "react",
            "@types/raect",
            "og",
            "os",
            "lodahs",
            "typescritp",
            "unrelated-catalog",
        ):
            # Give similarity controls exact inert metadata, independently of their spelling.
            key = "offline-package/package.json"
            yield (
                name,
                old,
                {
                    "package.json": json_bytes({"dependencies": {name: "file:./offline-package"}}),
                    key: json_bytes({"name": name, "version": "1.0.0"}),
                },
            )
        return
    key = "phantom-dep/package.json"
    src = "src/app.mjs"
    initial = {
        "package.json": (root / "after.json").read_bytes(),
        key: (root / key).read_bytes(),
        src: (root / src).read_bytes(),
    }
    yield "new unused install declaration", old, initial
    for label, source in (
        ("imported subpath", b'import "phantom-dep/catalog";'),
        ("dynamic unknown", b"export function load(name){return import(name)}"),
    ):
        yield label, old, {**initial, src: source}
    tool = {**json.loads(initial[key]), "bin": {"catalog-build": "bin.js"}}
    yield (
        "documented build command",
        old,
        {
            **initial,
            key: json_bytes(tool),
            "package.json": json_bytes(
                {**json.loads(initial["package.json"]), "scripts": {"build": "catalog-build"}}
            ),
        },
    )
    yield (
        "hook-free addition",
        old,
        {**initial, key: json_bytes({"name": "phantom-dep", "version": "1.0.0"})},
    )
    yield "unchanged dependency", initial, initial
    yield "missing metadata", old, {p: v for p, v in initial.items() if p != key}


def measure(before, files):
    with tempfile.TemporaryDirectory(prefix="laundromat-fixture-") as tmp:
        root = Path(tmp)
        (root / ".laundromat-fixture").touch()
        for name, data in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        snap, inputs = snapshot(root, list(files))
        return pipeline.inspect(
            {"snapshot": snap, "baseline_known": True}, inputs, before_files=before
        )


def run(scenario):
    rows = []
    for label, before, files in examples(scenario):
        try:
            result = measure(before, files)
        except (OSError, ValueError, TypeError) as exc:
            result = {"status": "incomplete", "issues": [str(exc)], "findings": []}
        rows.append(dict(case=label, **result))
    result = {"scenario": scenario, "provenance": "fresh synthetic fixtures", "cases": rows}
    if scenario == "supply-chain":
        result["lifecycle_calibration"] = sandbox.run(sandbox.request("calibration"), mode="strict")
    return result
