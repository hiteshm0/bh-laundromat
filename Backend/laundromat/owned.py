"""Evidence for a closed catalog of ordinary fixture tests."""

import difflib
from . import sandbox
from .snapshot import TOKEN
from .workspace import digest

EXPECTED = {
    "argv": {"calls": [["catalog", ["amber"]], ["catalog", ["indigo blue"]]]},
    "roles": {
        "messages": [
            {"role": "system", "content": "Summarize"},
            {"role": "user", "content": "ordinary catalog text"},
        ]
    },
    "access": {"decisions": [401, 200]},
    "configuration": {"reads_environment": True},
    "advisory": {"resolved": "4.17.19", "regression": True, "actual": [[101, 109], [104], []]},
}


def observe(test, data):
    r = sandbox.run(sandbox.request(test, data), data, "strict")
    if r["status"] == "complete":
        r["status"] = "pass" if r["observations"] == EXPECTED[test] else "fail"
    return r


def patch_text(path, original, candidate):
    return TOKEN.sub(
        "[redacted]",
        "".join(
            difflib.unified_diff(
                original.decode().splitlines(True),
                candidate.decode().splitlines(True),
                fromfile="a/" + path,
                tofile="b/" + path,
            )
        ),
    )


def audit(test, original, candidate, before=None):
    item = sandbox.OWNED[test]
    if original != sandbox.owned_bytes(test, "before") or candidate != sandbox.owned_bytes(
        test, "after"
    ):
        raise ValueError("Outside reviewed fixture adapter")
    before = before or observe(test, original)
    after = observe(test, candidate)
    verified = before["status"] == "fail" and after["status"] == "pass"
    static = {}
    if test == "advisory":
        from .detect import dependencies

        static = {
            "original_ranges": [f["evidence"] for f in dependencies(original, item["path"])],
            "candidate_ranges": [f["evidence"] for f in dependencies(candidate, item["path"])],
        }
        verified = verified and bool(static["original_ranges"]) and not static["candidate_ranges"]
    patch = patch_text(item["path"], original, candidate)
    return dict(
        static_evidence=static,
        test_id=test,
        property=item["property"],
        suite="owned-v1",
        suite_digest=sandbox.suite_digest(),
        path=item["path"],
        origin="template",
        state="candidate",
        verdict="verified" if verified else "incomplete",
        reason=None if verified else "Fixture did not transition from failure to pass",
        original_sha256=digest(original),
        candidate_sha256=digest(candidate),
        candidate=candidate.decode(),
        diff=patch,
        patch_sha256=digest(patch.encode()),
        before=before,
        after=after,
        elapsed_ms=before["duration_ms"] + after["duration_ms"],
    )
