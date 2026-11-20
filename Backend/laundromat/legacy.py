import json

from . import history, review
from .detect import finding
from .workspace import digest, plain


def load(path):
    path = review.resolve_receipt(path)
    _, work = review.receipt_workspace(path)
    if path.name != "receipt.json":
        raise ValueError("Expected an original Phase 1 run receipt")
    raw = path.read_bytes()
    r = json.loads(raw)
    actual, reason = review.verdict(r)
    if r["schema_version"] != 1 or actual != r["verdict"]:
        raise ValueError("Phase 1 verdict mismatch")
    snapshot = dict(r["snapshot"], repository=str(work), revision=None, issues=[])
    request = dict(
        trigger="replayed Phase 1 receipt",
        snapshot=snapshot,
        scope=list(snapshot["files"]),
        receipt_sha256=digest(raw),
    )
    hits = []
    if h := r.get("finding"):
        hits.append(
            finding(
                "query",
                h["rule_id"],
                h["file"],
                h["line"],
                "P3",
                "Semgrep",
                h["message"],
                scanned_sha256=h["scanned_sha256"],
            )
        )
    result = dict(
        status="incomplete" if actual == "incomplete" else "findings" if hits else "clean",
        findings=hits,
        coverage={"query": {"status": r["before"]["semgrep"]["status"]}},
        issues=[reason] if reason else [],
        elapsed_ms=r["elapsed_ms"],
    )
    if r.get("repair"):
        data = plain(path.parent / "repair.diff").read_bytes()
        if digest(data) != r["repair"]["patch_sha256"]:
            raise ValueError("Phase 1 patch hash mismatch")
        original = plain(path.parent / "before" / "search.js").read_bytes()
        candidate = plain(path.parent / "candidate" / "search.js").read_bytes()
        if (
            digest(original) != snapshot["files"]["search.js"]
            or candidate != review.template(original, r["finding"]["line"])
            or digest(candidate) != r["repair"]["candidate_sha256"]
            or review.diff(original, candidate) != data
        ):
            raise ValueError("Phase 1 candidate integrity mismatch")
        result["repair"] = dict(
            imported=True,
            source_receipt=str(path),
            origin="template",
            property="parameter binding",
            state="imported snapshot",
            suite="phase1-binding-v1",
            verdict=actual,
            diff=data.decode(),
            patch_sha256=digest(data),
            before=r["before"],
            after=r["after"],
        )
    sid = history.submit(request, state="importing")
    history.finish(sid, result)
    return sid
