"""End-to-end checks through the installed CLI, in a disposable test checkout."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


class PhaseOne(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        for relative in ("demo", "Backend/laundromat", "Backend/rules"):
            shutil.copytree(REPO / relative, self.root / relative)
        self.env = {**os.environ, "PYTHONPATH": str(self.root / "Backend")}
        self.cli = shutil.which("laundromat")
        self.assertIsNotNone(self.cli, "Activate the editable install first.")
        self.invoke("setup")
        self.work = self.root / ".laundromat/workspace"

    def invoke(self, *args, code=0):
        result = subprocess.run(
            [self.cli, *args], cwd=self.root, env=self.env, capture_output=True, text=True, timeout=90,
        )
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result.stdout if not result.stderr else result.stdout + result.stderr

    def test_review_apply_undo_and_drift(self):
        first = json.loads(self.invoke("demo", "--json"))
        self.invoke("reset")
        second = json.loads(self.invoke("demo", "--json"))
        for field in ("snapshot", "finding", "repair", "before", "after", "verdict"):
            self.assertEqual(first[field], second[field], field)
        self.assertEqual(second["verdict"], "verified")
        self.assertEqual(second["finding"]["file"], "search.js")
        self.assertEqual(second["finding"]["line"], 2)
        self.assertEqual(second["repair"]["source"], "template")
        for phase, expected_binding, hits in (("before", "fail", 1), ("after", "pass", 0)):
            checks = second[phase]
            self.assertEqual(checks["binding"]["status"], expected_binding)
            self.assertEqual(len(checks["semgrep"]["findings"]), hits)
            self.assertEqual(checks["semgrep"]["negative_control"], "pass")
            self.assertEqual(set(checks["semgrep"]["scanned"]), {"search.js", "safe-search.js"})
            ids = {row["term"]: row["actual"] for row in checks["sqlite"]["results"]}
            self.assertEqual(ids, {"amber": [101, 109], "indigo": [104], "jade": []})

        receipt = self.root / second["receipt"]
        self.assertEqual(json.loads(receipt.read_bytes()), second)
        target = self.work / "search.js"
        original = (self.root / "demo/fixture/search.js").read_bytes()
        self.assertEqual(target.read_bytes(), original)
        control = self.work / "safe-search.js"
        control.write_bytes(control.read_bytes() + b"// unrelated edit\n")
        captured = {p.name: p.read_bytes() for p in self.work.iterdir()}
        patch = receipt.parent / "repair.diff"
        reviewed_diff = patch.read_bytes()
        self.assertEqual(hashlib.sha256(reviewed_diff).hexdigest(), second["repair"]["patch_sha256"])
        patch.write_bytes(reviewed_diff + b"unreviewed change\n")
        self.assertIn("reviewed repair", self.invoke("apply", receipt, code=2))
        self.assertEqual(target.read_bytes(), original)
        patch.write_bytes(reviewed_diff)
        self.invoke("apply", receipt)
        self.assertEqual(
            [p.name for p in self.work.iterdir() if p.read_bytes() != captured[p.name]], ["search.js"]
        )
        applied = target.read_bytes()
        self.assertEqual(hashlib.sha256(applied).hexdigest(), second["repair"]["candidate_sha256"])
        self.assertEqual((receipt.parent / "original.bin").read_bytes(), original)
        target.write_bytes(applied + b"// later edit\n")
        self.assertIn("Stale undo", self.invoke("undo", receipt, code=2))
        self.assertEqual(target.read_bytes(), applied + b"// later edit\n")
        target.write_bytes(applied)
        self.invoke("undo", receipt)
        self.assertEqual({p.name: p.read_bytes() for p in self.work.iterdir()}, captured)
        target.write_bytes(original + b"// stale scan\n")
        self.assertIn("Stale apply", self.invoke("apply", receipt, code=2))
        self.assertEqual(target.read_bytes(), original + b"// stale scan\n")
        self.assertEqual((self.root / "demo/fixture/search.js").read_bytes(), original)

    def test_reset_scope(self):
        outside = self.root / "notes"
        outside.mkdir()
        keep = outside / "keep.txt"
        keep.write_text("keep this edit")
        (self.work / "notes").symlink_to(outside, target_is_directory=True)
        self.invoke("reset")
        self.assertEqual(keep.read_text(), "keep this edit")
        self.assertFalse((self.work / "notes").exists())
        (self.work.parent / ".phase1-workspace").unlink()
        (self.work / "local.txt").write_text("unmarked directory")
        self.invoke("reset", code=2)
        self.assertEqual((self.work / "local.txt").read_text(), "unmarked directory")

    def test_missing_scanner(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (bin_dir / "node").symlink_to(shutil.which("node"))
        self.env["PATH"] = str(bin_dir)
        receipt = json.loads(self.invoke("demo", "--json", code=2))
        self.assertEqual(receipt["verdict"], "incomplete")
        self.assertIn("semgrep", receipt["reason"])
        self.assertIsNone(receipt["repair"])
        self.assertTrue((self.root / receipt["receipt"]).is_file())
        self.assertIn("verified repair", self.invoke("apply", receipt["receipt"], code=2))

    def test_incorrect_expected_ids_block_verification(self):
        cases = self.root / "demo/cases.json"
        data = json.loads(cases.read_bytes())
        data[0]["ids"].reverse()
        cases.write_text(json.dumps(data))
        receipt = json.loads(self.invoke("demo", "--json", code=1))
        self.assertEqual(receipt["verdict"], "unverified")
        self.assertEqual(receipt["after"]["binding"]["status"], "pass")
        self.assertEqual(receipt["after"]["sqlite"]["results"][0]["status"], "fail")
        self.assertIn("verified repair", self.invoke("apply", receipt["receipt"], code=2))
