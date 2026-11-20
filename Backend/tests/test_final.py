import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from laundromat import detect, gate, history, pipeline, provider, repair, service
from laundromat.api import app
from laundromat.snapshot import snapshot, delta
from laundromat.workspace import FIXTURE, ROOT


class LocalReview(unittest.TestCase):
    def test_scope_and_change_types(self):
        before, old = snapshot(self.repo)
        (self.repo / "safe-search.js").unlink()
        (self.repo / "search.js").write_bytes(old["search.js"] + b"\n")
        (self.repo / "new.txt").write_text("untracked addition")
        after, new = snapshot(self.repo)
        changes = delta(before, after, old, new)
        self.assertEqual(
            {c["path"]: c["change"] for c in changes},
            {"safe-search.js": "deleted", "search.js": "modified", "new.txt": "added"},
        )
        result = json.loads(self.cli("scan", self.repo, "--path", "absent.js", "--json", code=2))
        self.assertIn("Requested file is missing", result["issues"][0])

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.repo = self.base / "repo"
        shutil.copytree(FIXTURE / "fixture", self.repo)
        env = patch.dict(os.environ, {"LAUNDROMAT_HOME": str(self.base / "ledger")})
        env.start()
        self.addCleanup(env.stop)

    def cli(self, *args, code=0, env=None):
        p = subprocess.run(
            ["laundromat", *map(str, args)], env=env, capture_output=True, text=True, timeout=100
        )
        self.assertEqual(p.returncode, code, p.stdout + p.stderr)
        return p.stdout

    def test_api_idempotency_restart_and_offline_evidence(self):
        name = str(self.repo)
        self.cli("register", name)
        body = {"repository": name, "scope": ["safe-search.js"], "idempotency_key": "same"}
        with TestClient(app) as client:
            first = client.post("/scans", json=body)
            self.assertEqual(first.status_code, 202)
            sid = first.json()["id"]
            self.assertEqual(client.post("/scans", json=body).json()["id"], sid)
            self.assertEqual(
                client.post("/scans", json={**body, "scope": ["search.js"]}).status_code, 409
            )
            for _ in range(160):
                value = client.get("/scans/" + sid).json()
                if value["job"]["state"] == "done":
                    break
                time.sleep(0.05)
            self.assertEqual(value["status"], "clean")
            observed = client.get("/events").json()
            self.assertEqual([e["kind"] for e in observed], ["queued", "running", "clean"])
            self.assertEqual(
                client.get("/events?after=" + str(observed[0]["id"])).json(), observed[1:]
            )
        offline = json.loads(self.cli("scan", name, "--path", "search.js", "--json"))
        with TestClient(app) as client:
            self.assertEqual(client.get("/scans/" + sid).json(), value)
            self.assertEqual(client.get("/scans/" + offline["id"]).json(), offline)
            self.assertEqual(client.get("/events").json()[: len(observed)], observed)
        with history.database() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM jobs WHERE scan=?", (sid,)).fetchone()[0], 1
            )

    def test_worker_crash_retry_and_snapshot_drift(self):
        sid = service.enqueue(self.repo, ["search.js"])
        # Terminate the worker process after it has committed its running state.
        code = "import os,sys; from laundromat import pipeline,service; pipeline.inspect=lambda *a,**kw:os._exit(52); service.work(sys.argv[1])"
        self.assertEqual(subprocess.run([sys.executable, "-c", code, sid]).returncode, 52)
        service.work()
        self.assertEqual(history.detail(sid)["status"], "interrupted")
        recovered = json.loads(self.cli("retry", sid, "--json"))
        self.assertEqual(recovered["job"], {"state": "done", "attempts": 2})
        self.assertEqual(len(recovered["findings"]), 1)
        pending = service.enqueue(self.repo, ["safe-search.js"])
        (self.repo / "safe-search.js").write_text("// concurrent edit\n")
        service.work(pending)
        self.assertIn("no longer matches", history.detail(pending)["issues"][0])

    def test_controls_model_and_stale_change(self):
        raw = "LMTEST_" + "A" * 24
        (self.repo / "settings.txt").write_text(raw)
        with patch.dict(os.environ, {"OPENAI_API_KEY": "", "LAUNDROMAT_MODEL": ""}):
            output = self.cli("scan", self.repo, "--model", "--json")
        self.assertNotIn(raw, output)
        self.assertNotIn(raw, provider.context({"settings.txt": raw}))
        scan = json.loads(output)
        self.assertIn("Model unavailable", scan["repair"]["model_issue"])
        self.assertEqual(scan["repair"]["origin"], "template")
        self.assertEqual({f["category"] for f in scan["findings"]}, {"secret", "query"})
        with history.database() as db:
            self.assertNotIn(raw, "".join(db.iterdump()))
        new = repair.REPLACEMENT.replace(b'"', b"'").decode()
        model = dict(
            categories=["query"],
            candidate=dict(path="search.js", replacement=new),
            explanation="Bind the term.",
        )
        response = {
            "status": "completed",
            "model": "recorded-parser-test",
            "usage": {"total_tokens": 12},
            "output": [{"content": [{"type": "output_text", "text": json.dumps(model)}]}],
        }
        with (
            patch.dict(
                os.environ, {"LAUNDROMAT_PROVIDER": "openai", "OPENAI_API_KEY": "test", "LAUNDROMAT_MODEL": "recorded-parser-test"}
            ),
            patch(
                "urllib.request.urlopen", return_value=io.BytesIO(json.dumps(response).encode())
            ) as transport,
        ):
            sid = service.enqueue(self.repo, key="recorded-model-fixture", model=True)
            service.work(sid)
            self.assertNotIn(raw, transport.call_args.args[0].data.decode())
            self.assertNotIn("settings.txt", transport.call_args.args[0].data.decode())
        r = history.detail(sid)["repair"]
        self.assertEqual((r["origin"], r["verdict"]), ("model", "verified"))
        target = self.repo / "search.js"
        orig = target.read_bytes()
        target.write_bytes(orig + b"// edited\n")
        self.assertIn("Stale apply", self.cli("apply", sid, "--json", code=2))
        target.write_bytes(orig)
        with patch.object(history, "event", side_effect=RuntimeError("abrupt stop")):
            with self.assertRaises(RuntimeError):
                repair.change(sid, False)
        self.cli("apply", sid)
        applied = target.read_bytes()
        target.write_bytes(applied + b"// edited\n")
        self.assertIn("Stale undo", self.cli("undo", sid, "--json", code=2))
        target.write_bytes(applied)
        self.cli("undo", sid)
        self.assertEqual(target.read_bytes(), orig)
        for bad in (
            {"path": "another.js", "replacement": new},
            {"path": "search.js", "replacement": "unknown()"},
        ):
            with self.assertRaises(ValueError):
                repair.fix(orig, 2, bad)

    def test_static_controls_and_unknown_data(self):
        src = (FIXTURE / "recorded" / "routes.js").read_bytes()
        hits, routes, issues = detect.guards(src, "routes.js")
        self.assertEqual((len(hits), len(routes), issues), (1, 3, []))
        self.assertEqual(hits[0]["evidence"]["expected"], "requireUser")
        deps = detect.dependencies(
            (FIXTURE / "recorded/package-lock.json").read_bytes(), "package-lock.json"
        )
        self.assertEqual([h["evidence"]["resolved"] for h in deps], ["4.17.18"])
        self.assertIsNone(detect.install_change(b'{"name":"sample"}')["gained"])
        self.assertTrue(
            detect.install_change((FIXTURE / "recorded/recorded-package.json").read_bytes())[
                "parent_references"
            ]
        )
        with patch.object(detect, "RULES", self.base / "absent"):
            with self.assertRaises(OSError):
                detect.dependencies(b"{}", "package-lock.json")
        unsafe = (self.repo / "search.js").read_bytes() + b"\nthrow new Error('must never run');\n"
        result = pipeline.inspect({"snapshot": {"issues": []}}, {"search.js": unsafe})
        self.assertIn("unsupported", result["findings"][0]["repair_status"])
        self.assertNotIn("repair", result)

    def test_import_and_reset_preserve_evidence(self):
        checkout = self.base / "checkout"
        for relative in ("Backend/laundromat", "Backend/rules", "demo"):
            shutil.copytree(ROOT / relative, checkout / relative)
        env = {**os.environ, "PYTHONPATH": str(checkout / "Backend")}
        self.cli("setup", env=env)
        receipt = json.loads(self.cli("demo", "--json", env=env))
        path = checkout / receipt["receipt"]
        original = path.read_bytes()
        imported = json.loads(self.cli("import-receipt", path, "--json", env=env))
        self.assertEqual(path.read_bytes(), original)
        self.cli("apply", path, env=env)
        self.cli("undo", path, env=env)
        self.cli("reset", env=env)
        self.assertFalse(path.exists())
        self.assertEqual(json.loads(self.cli("show", imported["id"], "--json", env=env)), imported)

    def test_push_inputs_and_hook_conflicts(self):
        def run(*args):
            return subprocess.run(
                ["git", "-C", str(self.repo), *args], capture_output=True, check=True
            )

        run("init", "-q")
        run("add", ".")
        run(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=review@example.invalid",
            "commit",
            "-qm",
            "Fixture",
        )
        tip = run("rev-parse", "HEAD").stdout.decode().strip()
        zero = "0" * 40
        for lines in ("", f"(delete) {zero} refs/heads/old {tip}"):
            self.assertEqual(gate.decide(self.repo, "", lines)["push_decision"]["action"], "allow")
        base = "a" * 40
        bad = gate.decide(self.repo, "", f"refs/heads/new {tip} refs/heads/new {base}")
        self.assertEqual(bad["status"], "incomplete")
        path = self.repo / ".git/hooks/pre-push"
        path.write_text("# existing team hook\n")
        with self.assertRaises(ValueError):
            gate.install(self.repo)
        self.assertEqual(path.read_text(), "# existing team hook\n")
        run("config", "core.hooksPath", "custom")
        with self.assertRaises(ValueError):
            gate.install(self.repo)
        self.assertEqual(run("config", "core.hooksPath").stdout.strip(), b"custom")

    def test_real_pushes(self):
        p = subprocess.run(
            [sys.executable, str(ROOT / "scripts/final_demo.py"), "--extended"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("1/1 rehearsals passed", p.stdout)
        repo = next(history.home().glob("rehearsal-*/outgoing"))
        mixed = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "push",
                "local",
                "main:review-clean",
                "intermediate:review-dirty",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(mixed.returncode, 0)
        latest = history.detail(history.listing()[0]["id"])
        self.assertEqual(latest["push_decision"]["action"], "block")
        self.assertEqual(
            {u["remote"] for u in latest["updates"]},
            {"refs/heads/review-clean", "refs/heads/review-dirty"},
        )
        refs = subprocess.check_output(
            ["git", "-C", str(repo.parent / "remote.git"), "for-each-ref", "--format=%(refname)"],
            text=True,
        )
        self.assertNotIn("refs/heads/review-", refs)
