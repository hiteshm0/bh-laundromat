"""Review npm declarations and parse parent source without loading its modules."""

import json
import re
from http.client import HTTPException
from pathlib import PurePosixPath as P
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from tree_sitter import Language, Parser
import tree_sitter_javascript as javascript
import tree_sitter_typescript as typescript

from .workspace import ASSETS, digest, json_bytes

RULES = ASSETS / "rules"
SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
EXCLUDED = {"node_modules", "vendor", "dist", "build", "coverage", ".next", ".git"}
LANGUAGES = {
    ".js": Language(javascript.language()),
    ".ts": Language(typescript.language_typescript()),
    ".tsx": Language(typescript.language_tsx()),
}
SOURCE = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx"}


def declarations(doc):
    deps = {}
    for section in SECTIONS:
        entries = doc.get(section, {})
        if not isinstance(entries, dict) or not all(isinstance(v, str) for v in entries.values()):
            raise ValueError("Unsupported npm dependency declarations")
        deps.update(entries)
    return deps


def manifest_additions(before, after):
    old, new = declarations(json.loads(before)), declarations(json.loads(after))
    return {name: new[name] for name in sorted(new.keys() - old.keys())}


def check_registry_existence(names: list[str]) -> dict[str, bool | None]:
    from .snapshot import TOKEN

    result = {}
    for name in dict.fromkeys(names):
        if name.startswith("file:") or TOKEN.search(name):
            continue
        url = "https://registry.npmjs.org/" + quote(name, safe="")
        try:
            with urlopen(Request(url, method="HEAD"), timeout=4) as response:
                result[name] = True if 200 <= response.status < 300 else None
        except HTTPError as exc:
            result[name] = False if exc.code == 404 else None
            exc.close()
        except (OSError, HTTPException, ValueError):
            result[name] = None
    return result


def hallucinated_packages(path, additions):
    from .detect import finding

    # Local dependencies, aliases, tarballs and Git references need no package
    # registered under the manifest key.
    names = [name for name, spec in additions.items() if not re.search(r"[:/]", spec)]
    return [
        finding(
            "slopsquatting", "npm.registry-404.v1", path, None, "P3", "live npm registry",
            f"{name} was not found in the npm registry (HTTP 404). "
            "This may be a hallucinated or mistyped package name. "
            "Verify the correct package name before running npm install.",
            package=name, registry_status="not_found",
            registry_url="https://www.npmjs.com/package/" + quote(name, safe="@/"),
        )
        for name, exists in check_registry_existence(names).items() if exists is False
    ]


def parse_source(path, data):
    suffix = P(path).suffix
    lang = ".tsx" if suffix == ".tsx" else ".ts" if suffix in (".ts", ".cts", ".mts") else ".js"
    return Parser(LANGUAGES[lang]).parse(data).root_node


def literals(path, data):
    root = parse_source(path, data)
    stack, refs, unknown = [root], set(), root.has_error
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        value = None
        if node.type in ("import_statement", "export_statement"):
            value = node.child_by_field_name("source")
            if node.type == "import_statement" and value is None:
                unknown = True
        elif node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn and fn.text in (b"import", b"require", b"require.resolve"):
                args = node.child_by_field_name("arguments")
                if args and len(args.named_children) == 1:
                    value = args.named_children[0]
                if value is None or value.type != "string":
                    unknown = True
            elif fn and fn.text in (b"eval", b"module.require", b"createRequire"):
                unknown = True
        elif (
            node.type == "identifier"
            and node.text == b"require"
            and node.parent.type != "call_expression"
        ):
            unknown = True
        if value is not None and value.type == "string":
            spec = value.text.decode()[1:-1]
            if "\\" in spec:
                unknown = True
            else:
                refs.add(spec)
    return refs, unknown


def local_dir(parent, spec):
    if not spec.startswith("file:"):
        return None
    rel = P(spec[5:])
    if not rel.parts or rel.is_absolute() or ".." in rel.parts:
        return None
    return parent / rel


def dependency_structure(path, before, files, *, complete=True):
    from .detect import finding

    parent = P(path).parent
    doc = json.loads(files[path])
    deps = declarations(doc)
    local = {d for spec in deps.values() if (d := local_dir(parent, spec))}
    entries = json.loads((RULES / "npm-metadata-v1.json").read_bytes())["packages"]
    observations, hits = [], []
    for name, spec in manifest_additions(before, files[path]).items():
        location = local_dir(parent, spec)
        meta, origin = None, None
        if location:
            key = str(location / "package.json")
            if key in files:
                meta, origin = json.loads(files[key]), key
        elif name + "@" + spec in entries:
            meta, origin = entries[name + "@" + spec], "npm-metadata-v1"
        o = dict(
            package=name,
            requested=spec,
            metadata=origin,
            searched_paths=[],
            hooks=[],
            source_references=[],
            tool_commands=[],
            config_references=[],
            coverage="complete",
            status="checked-negative",
        )
        observations.append(o)
        if (
            not isinstance(meta, dict)
            or meta.get("name") != name
            or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", str(meta.get("version", "")))
            or not isinstance(meta.get("scripts", {}), dict)
        ):
            o.update(
                coverage="unknown", status="unknown", reason="Exact package metadata unavailable"
            )
            continue
        o.update(resolved=meta["version"], metadata_sha256=digest(json_bytes(meta)))
        o["hooks"] = sorted(
            {"preinstall", "install", "postinstall"} & meta.get("scripts", {}).keys()
        )
        if not o["hooks"]:
            continue
        incomplete = not complete
        for k, data in sorted(files.items()):
            p = P(k)
            if (
                not p.is_relative_to(parent)
                or EXCLUDED.intersection(p.parts)
                or any(p.is_relative_to(d) for d in local)
            ):
                continue
            if p.suffix in SOURCE:
                o["searched_paths"].append(k)
                refs, ambiguous = literals(k, data)
                incomplete |= ambiguous
                if any(r == name or r.startswith(name + "/") for r in refs):
                    o["source_references"].append(k)
            elif p.suffix in {".vue", ".svelte", ".astro", ".coffee", ".mdx", ".html"} or (
                p != P(path) and p.name == "package.json"
            ):
                incomplete = True
        bins = meta.get("bin", {})
        commands = {name.rsplit("/", 1)[-1]} if isinstance(bins, str) else set(bins)
        for label, cmd in doc.get("scripts", {}).items():
            if isinstance(cmd, str) and cmd.split() and cmd.split()[0] in commands:
                o["tool_commands"].append(label)
            elif cmd and not re.fullmatch(r"node [./\w-]+", cmd):
                incomplete = True
        for key in ("babel", "eslintConfig", "jest"):
            if key not in doc:
                continue
            configured = doc[key]
            if isinstance(configured, dict):
                for field in ("plugins", "extends", "presets", "preset", "setupFiles"):
                    values = configured.get(field, [])
                    if isinstance(values, str):
                        values = [values]
                    if isinstance(values, list) and any(
                        isinstance(v, str) and (v == name or v.startswith(name + "/"))
                        for v in values
                    ):
                        o["config_references"].append(path + "#" + key + "." + field)
            incomplete = True
        for filename in files:
            p = P(filename)
            if (
                p.is_relative_to(parent)
                and not EXCLUDED.intersection(p.parts)
                and not any(p.is_relative_to(d) for d in local)
            ):
                if (
                    p.name in ("tsconfig.json", ".babelrc", ".eslintrc", ".eslintrc.json")
                    or ".config." in p.name
                ):
                    incomplete = True
        if "workspaces" in doc or "imports" in doc:
            incomplete = True
        if o["source_references"] or o["tool_commands"] or o["config_references"]:
            o["reason"] = "Recognized parent use"
        elif incomplete:
            o.update(
                coverage="unknown",
                status="unknown",
                reason="Partial scope, configuration or dynamic reference",
            )
        else:
            o["status"] = "review"
            hits.append(
                finding(
                    "supply-chain",
                    "npm.unused-install-hook.v1",
                    path,
                    None,
                    "P2",
                    "local manifest and parsed parent source",
                    f"{name} declares {', '.join(o['hooks'])}. No recognized use in "
                    + (", ".join(o["searched_paths"]) or "the enumerated parent sources")
                    + ".",
                    **o,
                )
            )
    return hits, observations


def distance(a, b):
    # Unrestricted Damerau–Levenshtein (including repeated letters).
    n, m = len(a), len(b)
    bound = n + m
    d = [[0] * (m + 2) for _ in range(n + 2)]
    for i in range(n + 1):
        d[i + 1][0], d[i + 1][1] = bound, i
    for j in range(m + 1):
        d[0][j + 1], d[1][j + 1] = bound, j
    d[0][0] = bound
    seen = {}
    for i, x in enumerate(a, 1):
        match = 0
        for j, y in enumerate(b, 1):
            i1, j1 = seen.get(y, 0), match
            if x == y:
                match = j
            d[i + 1][j + 1] = min(
                d[i][j] + (x != y),
                d[i + 1][j] + 1,
                d[i][j + 1] + 1,
                d[i1][j1] + i - i1 - 1 + 1 + j - j1 - 1,
            )
        seen[x] = i
    return d[-1][-1]


def similar_names(path, additions):
    from .detect import finding

    index = json.loads((RULES / "names-v1.json").read_bytes())
    hits = []
    for name in additions:
        norm = name.lower()
        scope, _, leaf = norm.rpartition("/")
        if norm in index["names"] or not 2 <= len(leaf) <= 214:
            continue
        choices = [
            (distance(leaf, n.rpartition("/")[2]), n)
            for n in index["names"]
            if n.rpartition("/")[0] == scope
        ]
        if not choices:
            continue
        best = min(choices)[0]
        if best <= (2 if len(leaf) >= 8 else 1):
            nearest = sorted(n for d, n in choices if d == best)
            hits.append(
                finding(
                    "slopsquatting",
                    "npm.similar-name.v1",
                    path,
                    None,
                    "P4",
                    "offline npm name index",
                    f"Name-similarity warning for {name}. Nearest: {', '.join(nearest)}.",
                    package=name,
                    nearest=nearest,
                    distance=best,
                    ambiguous=len(nearest) > 1,
                    index_version=index["version"],
                )
            )
    return hits
