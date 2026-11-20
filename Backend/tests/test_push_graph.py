import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

from scripts.push_demo import BOUND, ORIGINAL, SOURCE, Rehearsal


class PushGraph(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        mock_dir = Path(__file__).parent / "push_fixtures"
        env = dict(
            os.environ,
            LAUNDROMAT_HOME=str(self.folder / "ledger"),
            PYTHONPATH=str(mock_dir.resolve()),
            LAUNDROMAT_PROVIDER="openai",
            LAUNDROMAT_MODEL="mocked-push-test",
            OPENAI_API_KEY="local-mock-placeholder",
        )
        self.demo = Rehearsal(self.folder, env)
        self.demo.push(allowed=True)

    def expected_patch(self):
        d = self.demo
        path = d.repo / SOURCE
        original = path.read_text()
        path.write_text(original.replace(ORIGINAL, BOUND))
        expected = d.run("git", "diff", "--", SOURCE).stdout
        path.write_text(original)
        return expected

    def test_developer_approval_and_commit_observation(self):
        d = self.demo
        tip = d.introduce()
        path = d.repo / SOURCE
        expected_patch = self.expected_patch()
        original = path.read_bytes()
        r = d.push(allowed=False)
        self.assertEqual(r["mode"], "developer")
        self.assertEqual(d.git("diff", "--cached"), "")
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(len(r["push_reviews"]), 1)
        item = r["push_reviews"][0]
        self.assertEqual(item["introducing_commit"], tip)
        self.assertEqual(item["state"], "proposed", r["issues"])
        self.assertEqual(
            [(a["role"], a["origin"]) for a in item["role_calls"]],
            [(a, "mocked") for a in ("Detect", "Prove", "Fix")],
        )
        self.assertEqual(item["before"]["status"], "observed violation")
        self.assertEqual(item["after"]["status"], "pass")
        for phase in ("before", "after", "regression"):
            self.assertEqual(item[phase]["cleanup_status"], "removed")
        for field in ("test_sha256", "runtime", "regression_sha256", "adapter_sha256"):
            self.assertEqual(item["before"][field], item["after"][field])
        self.assertNotEqual(item["before"]["container_id"], item["after"]["container_id"])
        self.assertEqual(item["regression"]["status"], "pass")
        self.assertEqual(item["rescan"]["query_matches"], 0)
        self.assertEqual(d.push(allowed=False)["id"], r["id"])
        d.cli("approve", r["id"])
        d.cli("approve", r["id"])
        self.assertEqual(d.run("git", "diff", "--cached").stdout, expected_patch)
        self.assertEqual(d.git("diff"), "")
        staged = d.cli("show", r["id"])["push_reviews"][0]
        self.assertEqual(staged["patch"], staged["staged_diff"])
        d.git("commit", "-qm", "Bind aisle")
        d.push(allowed=True)
        self.assertEqual(
            d.cli("show", r["id"])["push_reviews"][0]["committed_oid"],
            d.git("rev-parse", "HEAD"),
        )

    def test_vibe_unrelated_index_and_worktree(self):
        d = self.demo
        d.env.update(LAUNDROMAT_PROVIDER="groq", GROQ_API_KEY="groq-mock-credential")
        d.introduce()
        patch = self.expected_patch()
        (d.repo / "notes.txt").write_text("staged note\n")
        d.git("add", "notes.txt")
        (d.repo / "notes.txt").write_text("separate unstaged note\n")
        prior = d.run("git", "diff", "--cached").stdout
        unstaged = d.run("git", "diff").stdout
        p = d.run("git", "status", "--porcelain").stdout
        from_subdir = subprocess.run(
            ["laundromat", "switch", "vibe-coder"],
            cwd=d.repo / "inventory",
            env=d.env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(from_subdir.stdout.strip(), "vibe-coder")
        self.assertEqual(d.cli("mode"), {"mode": "vibe-coder"})
        self.assertEqual(d.run("git", "status", "--porcelain").stdout, p)
        r = d.push(allowed=False)
        self.assertEqual(r["push_reviews"][0]["state"], "staged", r["issues"])
        self.assertEqual(d.run("git", "diff", "--cached").stdout, patch + prior)
        self.assertEqual(d.run("git", "diff").stdout, unstaged)
        self.assertEqual(d.push(allowed=False)["id"], r["id"])
        self.assertEqual(d.run("git", "diff", "--cached").stdout, patch + prior)

    def test_same_file_unrelated_changes_and_offline_dashboard_receipt(self):
        from fastapi.testclient import TestClient
        from laundromat.api import app
        from unittest.mock import patch

        d = self.demo
        d.introduce()
        path = d.repo / SOURCE
        original = path.read_text()
        path.write_text("// staged note\n" + original)
        d.git("add", SOURCE)
        path.write_text(path.read_text() + "// working note\n")
        before = path.read_text()
        # Compute the exact expected index without including the unstaged comment.
        path.write_text(("// staged note\n" + original).replace(ORIGINAL, BOUND))
        d.git("add", SOURCE)
        expected = d.run("git", "diff", "--cached").stdout
        path.write_text("// staged note\n" + original)
        d.git("add", SOURCE)
        path.write_text(before)
        d.run("laundromat", "switch", "vibe-coder")
        receipt = d.push(allowed=False)
        self.assertEqual(
            receipt["push_reviews"][0]["state"], "staged", receipt.get("staging_issue")
        )
        self.assertEqual(d.run("git", "diff", "--cached").stdout, expected)
        self.assertEqual(path.read_text(), before.replace(ORIGINAL, BOUND))
        with (
            patch.dict(os.environ, {"LAUNDROMAT_HOME": d.env["LAUNDROMAT_HOME"]}),
            TestClient(app) as api,
        ):
            scan = api.get("/scans/" + receipt["id"]).json()
            self.assertEqual(scan["push_reviews"], receipt["push_reviews"])
            states = [e["kind"] for e in api.get("/events").json() if e["scan"] == receipt["id"]]
            self.assertTrue({"flagged", "verified", "proposed", "staged"}.issubset(states))

    def test_stale_overlap_and_unassigned_push(self):
        d = self.demo
        d.introduce()
        d.run("laundromat", "switch", "vibe-coder")
        d.git("branch", "other")
        for refs in (("main", "other"), ("other",)):
            r = d.push(allowed=False, refs=refs)
            self.assertEqual(r["push_reviews"][0]["state"], "proposed")
            self.assertTrue(r["staging_issue"])
            self.assertEqual(d.run("git", "diff", "--cached").stdout, "")
        path = d.repo / SOURCE
        path.write_text(path.read_text().replace(ORIGINAL, "  return [];"))
        r = d.push(allowed=False)
        self.assertIn("local edits", r["staging_issue"])
        self.assertEqual(d.run("git", "diff", "--cached").stdout, "")
        self.assertNotEqual(d.run("laundromat", "approve", r["id"], check=False).returncode, 0)
        d.commit("Independent change")
        self.assertNotEqual(d.run("laundromat", "approve", r["id"], check=False).returncode, 0)
        self.assertEqual(d.run("git", "diff", "--cached").stdout, "")

    def test_unavailable_roles_invalid_output_and_candidate_failure(self):
        d = self.demo
        d.introduce()
        del d.env["OPENAI_API_KEY"]
        r = d.push(allowed=False)
        self.assertEqual(r["status"], "incomplete")
        self.assertEqual([t["role"] for t in r["push_reviews"][0]["role_calls"]], ["Detect"])
        d.env.update(OPENAI_API_KEY="local-mock-placeholder", MOCK_MALFORMED="1")
        r = d.push(allowed=False)
        self.assertEqual(r["push_reviews"][0]["role_calls"][0]["outcome"], "invalid")
        del d.env["MOCK_MALFORMED"]
        d.env["DOCKER_HOST"] = "unix:///unavailable-laundromat-test.sock"
        d.env.pop("DOCKER_CONTEXT", None)
        r = d.push(allowed=False)
        self.assertEqual(
            [t["role"] for t in r["push_reviews"][0]["role_calls"]], ["Detect", "Prove"]
        )
        self.assertEqual(r["push_reviews"][0]["before"]["status"], "incomplete")
        del d.env["DOCKER_HOST"]
        d.env["MOCK_BAD_PATCH"] = "1"
        r = d.push(allowed=False)
        self.assertEqual(r["status"], "incomplete")
        self.assertEqual(r["push_reviews"][0]["state"], "inconclusive")
        self.assertNotEqual(r["push_reviews"][0]["after"]["status"], "pass")
        self.assertEqual(d.run("git", "diff", "--cached").stdout, "")
        self.assertFalse(r["verified_actions"])
        self.assertNotIn(d.env["OPENAI_API_KEY"], json.dumps(r))
