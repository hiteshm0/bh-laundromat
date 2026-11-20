"""Static evidence adapters. The caller owns policy and verification."""

import json
import os
import re
import ssl
import subprocess
import tempfile
from pathlib import Path

from .manifests import (
    manifest_additions as manifest_additions,
    dependency_structure as dependency_structure,
    similar_names as similar_names,
)
from .checks import RULE
from .snapshot import TOKEN, relative
from .workspace import digest, json_bytes

RULES = RULE.parent


def finding(category, rule, path, line, severity, source, explanation, **evidence):
    fields = dict(
        category=category,
        rule=rule,
        path=path,
        line=line,
        severity=severity,
        source=source,
        explanation=explanation,
        evidence=evidence,
        repair_status="not proposed",
    )
    fields["id"] = digest(json_bytes(fields))[:24]
    if category == "secret":
        fields["push_policy"] = "review" if rule == "aws-access-id" else "block"
    elif category in ("dependency", "supply-chain"):
        fields["push_policy"] = "acknowledge"
    else:
        fields["push_policy"] = "review"
    return fields


def secrets(data, path, commit=None):
    argv = [
        "gitleaks",
        "stdin",
        "--config",
        str(RULES / "synthetic.toml"),
        "--redact=100",
        "--no-banner",
        "--no-color",
        "--ignore-gitleaks-allow",
        "--exit-code",
        "17",
        "--report-format",
        "json",
        "--report-path",
        "-",
    ]
    with tempfile.TemporaryDirectory() as tmp:
        p = subprocess.run(argv, cwd=tmp, input=data, capture_output=True, timeout=15)
    if p.returncode not in (0, 17):
        raise ValueError(f"Gitleaks exited {p.returncode}")
    hits = json.loads(p.stdout or b"[]")
    if bool(hits) != (p.returncode == 17):
        raise ValueError("Gitleaks report and exit status disagree")
    findings = {}
    for h in sorted(hits, key=lambda row: (row["StartLine"], row.get("StartColumn", 0))):
        hit = finding(
            "secret",
            h["RuleID"],
            path,
            h["StartLine"],
            "P3" if h["RuleID"] == "aws-access-id" else "P1",
            "Gitleaks",
            "Credential-shaped text matches the pinned rule. Review exposure and rotate with the owner if real.",
            commit=commit,
        )
        column = h.get("StartColumn")
        if column:
            # Preserve existing single-match IDs and distinguish additional
            # occurrences of the same rule on the same line.
            if hit["id"] in findings:
                hit["id"] = digest(json_bytes([hit["id"], column]))[:24]
            hit["evidence"]["column"] = column
        findings[hit["id"]] = hit
    return list(findings.values())


def queries(files):
    if not files:
        return [], None
    scanned_hashes = {}
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        for name, data in files.items():
            path = base / relative(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            masked = re.sub(TOKEN.pattern.encode(), lambda match: b"_" * len(match[0]), data)
            path.write_bytes(masked)
            scanned_hashes[name] = digest(masked)
        env = dict(
            os.environ,
            SEMGREP_SETTINGS_FILE=str(base / "settings.yml"),
            SEMGREP_LOG_FILE=str(base / "scan.log"),
        )
        if cafile := ssl.get_default_verify_paths().cafile:
            env.setdefault("SSL_CERT_FILE", cafile)
        argv = [
            "semgrep",
            "scan",
            "--config",
            str(RULE),
            "--config",
            str(RULES / "composed-query.yml"),
            "--metrics=off",
            "--disable-version-check",
            "--strict",
            "--no-git-ignore",
            "--disable-nosem",
            "--no-rewrite-rule-ids",
            "--jobs",
            "1",
            "--json",
            "--",
            *files,
        ]
        p = subprocess.run(argv, cwd=base, env=env, capture_output=True, timeout=30)
        if p.returncode:
            raise ValueError(f"Semgrep exited {p.returncode}")
        report = json.loads(p.stdout)
        if (
            report["errors"]
            or report.get("skipped_rules")
            or set(report["paths"]["scanned"]) != set(files)
        ):
            raise ValueError("Semgrep could not cover all selected JavaScript files")
    return [
        finding(
            "query",
            h["check_id"],
            h["path"],
            h["start"]["line"],
            "P3",
            "Semgrep",
            h["extra"]["message"],
            scanned_sha256=scanned_hashes[h["path"]],
            source_sha256=digest(files[h["path"]]),
        )
        for h in report["results"]
    ], report["version"]


ROUTE = re.compile(
    r"""router\.(?P<method>get|post|put|patch|delete)\(\s*(['"])(/[\w:/-]*)\2\s*,\s*([\w\s,]+)\s*\)\s*;"""
)
IDENT = re.compile(r"[A-Za-z_$][\w$]*")


def guards(data, path):
    policy = json.loads((RULES / "policy.json").read_bytes())["routes"]
    source = data.decode()
    matched, findings, issues = [], [], []
    offset = 0
    while offset < len(source):
        space = re.match(r"(?:\s+|//[^\n]*(?:\n|$))*", source[offset:])
        offset += space.end()
        if offset == len(source):
            break
        route = ROUTE.match(source, offset)
        if not route:
            issues.append(
                f"{path}: unsupported route declaration at line {source.count(chr(10), 0, offset) + 1}"
            )
            break
        offset = route.end()
        url = route[3]
        handlers = [part.strip() for part in route[4].split(",")]
        line = source.count("\n", 0, route.start()) + 1
        key = url if route["method"] == "get" else route["method"].upper() + " " + url
        if key not in policy or not all(IDENT.fullmatch(h) for h in handlers):
            issues.append(f"{path}:{line} outside the declared route policy")
            continue
        expected = policy[key]
        matched.append(
            {
                "method": route["method"],
                "route": url,
                "line": line,
                "expected": expected,
                "observed": handlers[:-1],
            }
        )
        if expected and expected not in handlers[:-1]:
            findings.append(
                finding(
                    "guard",
                    "team.route-policy.v1",
                    path,
                    line,
                    "P3",
                    "scoped static route rule",
                    "Protected route needs review.",
                    method=route["method"],
                    route=url,
                    expected=expected,
                    observed=handlers[:-1],
                )
            )
    return findings, matched, issues


def version(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value
    ):
        raise ValueError("Expected an exact three-part release version")
    return tuple(map(int, value.split(".")))


def dependencies(data, path):
    advisory = json.loads((RULES / "advisories.json").read_bytes())
    lock = json.loads(data)
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(lock.get("packages"), dict):
        raise ValueError("Only npm package-lock versions 2 and 3 are supported")
    findings = []
    for dep, meta in lock["packages"].items():
        name = meta.get("name") or dep.rsplit("node_modules/", 1)[-1]
        for a in advisory["entries"]:
            if name != a["name"] or a["ecosystem"] != "npm":
                continue
            resolved = meta.get("version")
            if version(a["introduced"]) <= version(resolved) < version(a["fixed"]):
                findings.append(
                    finding(
                        "dependency",
                        a["id"],
                        path,
                        None,
                        "P2",
                        "pinned offline advisory",
                        f"{name} {resolved} matches a recorded affected range.",
                        package=name,
                        resolved=resolved,
                        affected=f">={a['introduced']} <{a['fixed']}",
                        fixed=a["fixed"],
                        ecosystem="npm",
                        dependency_path=dep,
                        date=advisory["date"],
                        url=a["url"],
                        upgrade_test="not exercised",
                    )
                )
    return findings


def install_change(data):
    meta = json.loads(data)
    current, previous = meta.get("current") or {}, meta.get("previous") or {}
    names = {"preinstall", "install", "postinstall"}

    def release(record):
        value = record.get("version")
        try:
            version(value)
        except ValueError:
            return None
        return value

    old_version, new_version = release(previous), release(current)
    known = bool(
        old_version
        and new_version
        and all(isinstance(x.get("scripts"), dict) for x in (current, previous))
    )
    gained = (
        sorted((names & current["scripts"].keys()) - previous["scripts"].keys()) if known else None
    )
    parent = meta.get("parentSource")
    name = meta["name"]
    referenced = (
        None
        if parent is None
        else bool(
            re.search(
                r"""(?:require\(\s*|from\s+|import\s+)['"]""" + re.escape(name) + r"""['"]""",
                parent,
            )
        )
    )
    return dict(
        source="recorded package metadata",
        package=name,
        previous=old_version,
        resolved=new_version,
        gained=gained,
        parent_references=referenced,
    )


def boundaries(data, path):
    from .manifests import LANGUAGES, Parser

    # Restrict these policies to direct call/object syntax, including unsupported fixture variants.
    root = Parser(LANGUAGES[".js"]).parse(data).root_node
    stack, hits = [root], []
    while stack:
        n = stack.pop()
        stack.extend(n.named_children)
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if (
                fn
                and fn.text in (b"exec", b"run", b"child_process.exec")
                and args
                and any(
                    c.type == "binary_expression"
                    or (c.type == "template_string" and b"${" in c.text)
                    for c in args.named_children
                )
            ):
                hits.append(
                    finding(
                        "command",
                        "command.argument-boundary.v1",
                        path,
                        n.start_point.row + 1,
                        "P3",
                        "static argument policy",
                        "A command string incorporates a value.",
                    )
                )
        elif n.type == "object":
            values = {}
            for child in n.named_children:
                key, val = child.child_by_field_name("key"), child.child_by_field_name("value")
                if key and val:
                    values[key.text.strip(b"'\x22")] = val
            role, content = values.get(b"role"), values.get(b"content")
            if (
                role
                and role.text.strip(b"'\x22") in (b"system", b"developer")
                and content
                and content.type != "string"
            ):
                hits.append(
                    finding(
                        "prompt",
                        "prompt.role-boundary.v1",
                        path,
                        n.start_point.row + 1,
                        "P3",
                        "static message policy",
                        "Instruction-role content incorporates a value.",
                    )
                )
    return hits
