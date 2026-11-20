import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from laundromat import capture, detect, gate, history, proposal, repair, scenarios, service
from laundromat.snapshot import snapshot
from laundromat.workspace import FIXTURE, digest


class ProposalReview(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.repo = self.root / "repo"
        shutil.copytree(FIXTURE / "fixture", self.repo)
        env = patch.dict(
            os.environ, LAUNDROMAT_HOME=str(self.root / "ledger"), LAUNDROMAT_RUNTIME="local"
        )
        env.start()
        self.addCleanup(env.stop)

    def test_rejected_repaired_and_stale_proposal(self):
        target = self.repo / "search.js"
        original = target.read_bytes()
        note = self.repo / "untracked.txt"
        note.write_text("preserve me")

        def stage():
            return capture.capture(self.repo, "annotate-search", True, proposal=True)

        sid = stage()
        self.assertEqual(target.read_bytes(), original)
        r = proposal.decide(sid, "reject")
        self.assertEqual(r["proposal_state"], "rejected")
        self.assertEqual(target.read_bytes(), original)
        sid = stage()
        note.write_text("concurrent")
        with self.assertRaisesRegex(ValueError, "Stale"):
            proposal.decide(sid, "accept")
        self.assertEqual(target.read_bytes(), original)
        note.write_text("preserve me")
        seen = []
        from laundromat.workspace import atomic_write

        def write(p, b, *a):
            if p == target:
                seen.append(b)
            atomic_write(p, b, *a)

        with patch.object(proposal, "atomic_write", side_effect=write):
            r = proposal.decide(sid, "accept")
        self.assertEqual(seen, [r["repair"]["candidate"].encode()])
        self.assertEqual(r["findings"][0]["change"], "pre-existing")
        self.assertEqual(proposal.decide(sid, "undo")["working_sha256"], digest(original))
        self.assertEqual(note.read_text(), "preserve me")

    def test_static_outage_and_wrong_ids_disable_apply(self):
        with patch.object(detect, "queries", side_effect=FileNotFoundError("semgrep unavailable")):
            sid = service.enqueue(self.repo)
            service.work(sid)
        r = history.detail(sid)
        self.assertTrue(r["raw_candidates"])
        self.assertFalse(r["verified_actions"])
        with self.assertRaises(ValueError):
            repair.change(sid, False)
        from laundromat import checks

        original = checks.behavior

        def mismatch(source, cases, runtime=None):
            return original(
                source, [dict(c, ids=[999]) if c["term"] == "amber" else c for c in cases], runtime
            )

        with patch.object(checks, "behavior", side_effect=mismatch):
            sid = service.enqueue(self.repo, key="bad expected IDs")
            service.work(sid)
        r = history.detail(sid)
        self.assertEqual(r["findings"][0]["original_observations"]["sqlite"]["status"], "fail")
        self.assertFalse(r["verified_actions"])
        with self.assertRaises(ValueError):
            repair.change(sid, False)

    def test_structural_controls_and_parsing(self):
        results = {}
        for label, before, files in scenarios.examples("supply-chain"):
            hits, observations = detect.dependency_structure(
                "package.json", before["package.json"], files
            )
            results[label] = (len(hits), [o["status"] for o in observations])
        self.assertEqual(sum(n for n, _ in results.values()), 1)
        for label in ("dynamic unknown", "missing metadata"):
            self.assertEqual(results[label], (0, ["unknown"]))
        _, before, files = next(scenarios.examples("supply-chain"))
        for src in (
            'import "phantom-dep";',
            'export { title } from "phantom-dep/sub";',
            'const a=import("phantom-dep/sub");',
            'require("phantom-dep");',
        ):
            hits, obs = detect.dependency_structure(
                "package.json", before["package.json"], {**files, "src/app.ts": src.encode()}
            )
            self.assertFalse(hits)
            self.assertIn("src/app.ts", obs[0]["source_references"])
        _, obs = detect.dependency_structure(
            "package.json", before["package.json"], {**files, "src/app.ts": b"import !!!"}
        )
        self.assertEqual(obs[0]["status"], "unknown")
        for name, warning in (
            ("expres", True),
            ("experss", True),
            ("express", False),
            ("unrelated-catalog", False),
            ("@types/raect", True),
        ):
            self.assertEqual(bool(detect.similar_names("package.json", {name: "1.0.0"})), warning)
        self.assertTrue(
            detect.similar_names("package.json", {"os": "1.0.0"})[0]["evidence"]["ambiguous"]
        )

    def test_manifest_diff_cli_and_push(self):
        repo = self.root / "manifest"
        repo.mkdir()
        label, before, after = next(scenarios.examples("supply-chain"))
        for path, data in {**after, **before}.items():
            out = repo / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)

        def git(*args):
            return subprocess.check_output(["git", "-C", repo, *args]).decode().strip()

        def commit():
            git("add", ".")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            return git("rev-parse", "HEAD")

        git("init", "-q")
        base = commit()
        patchfile = FIXTURE / "supply-chain/proposal.diff"
        report = json.loads(
            subprocess.check_output(
                ["laundromat", "review", "--diff", patchfile, "--repo", repo, "--format", "json"]
            )
        )
        self.assertEqual([h["category"] for h in report["findings"]], ["supply-chain"])
        self.assertEqual((repo / "package.json").read_bytes(), before["package.json"])
        (repo / "package.json").write_bytes(after["package.json"])
        sid = service.enqueue(repo, ["package.json"])
        service.work(sid)
        self.assertEqual(history.detail(sid)["findings"][0]["category"], "supply-chain")
        tip = commit()
        result = gate.decide(repo, "", f"refs/heads/main {tip} refs/heads/main {base}")
        self.assertEqual(result["push_decision"]["action"], "acknowledge")
        self.assertEqual(result["findings"][0]["category"], "supply-chain")
        for bad in (
            patchfile.read_bytes().replace(b"a/package.json", b"a/../package.json"),
            patchfile.read_bytes().replace(b"laundromat-example", b"stale-example"),
            b"GIT binary patch",
        ):
            with self.assertRaises(ValueError):
                proposal.patched(before, bad)

    def test_replayed_rollback_uses_real_receipts(self):
        _, before, files = next(scenarios.examples("injection"))
        result = scenarios.measure(before, files)
        history.replay_rollback(files, result)
        self.assertEqual(
            result["rollback_observation"]["restored_sha256"], digest(files["search.js"])
        )
        self.assertEqual(
            [t["state"] for t in result["replayed_transitions"]], ["fixed", "restored"]
        )
        self.assertFalse(history.listing())

    def test_abandoned_decision_and_demo_isolation(self):
        sid = history.submit(
            {"trigger": "pre-push", "pid": 99999999, "snapshot": snapshot(self.repo)[0]},
            state="deciding",
        )
        service.work()
        self.assertIn("Retry the Git push", history.detail(sid)["recovery"])
        with self.assertRaisesRegex(ValueError, "Git push"):
            service.retry(sid)
        fake = {"status": "clean", "findings": []}
        with patch.object(scenarios, "measure", return_value=fake) as m:
            a = history.seed_demo_history()
            self.assertGreater(m.call_count, 20)
            m.reset_mock()
            self.assertEqual(a, history.seed_demo_history())
            m.assert_not_called()
        self.assertEqual(len(history.listing()), 1)
