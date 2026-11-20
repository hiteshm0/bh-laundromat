import json
import unittest
from unittest.mock import patch

from Research.evaluate_v1 import HERE, materialize, measured, score
from laundromat.workspace import digest


class Evaluation(unittest.TestCase):
    def test_frozen_groups_and_redaction(self):
        raw = (HERE / "manifest-v1.json").read_bytes()
        self.assertEqual(digest(raw), (HERE / "manifest-v1.sha256").read_text().split()[0])
        groups = {}
        for case in json.loads(raw)["cases"]:
            self.assertEqual(groups.setdefault(case["group"], case["split"]), case["split"])
            files, context = materialize(case)
            if case["group"] in ("secret/literal", "secret/encoded"):
                self.assertNotEqual(files["settings.txt"].decode(), context["settings.txt"])
                self.assertIn("[redacted", context["settings.txt"])

    def test_scoring_incomplete_zero_and_rejected_candidate(self):
        case = json.loads((HERE / "manifest-v1.json").read_bytes())["cases"][0]
        response = {
            "categories": ["query"],
            "candidate": {"path": "wrong.js", "replacement": "unsupported"},
            "model": "parser-test",
            "usage": {"total_tokens": 8},
            "explanation": "Use a bound value.",
        }
        with patch("laundromat.provider.ask", return_value=response):
            row = measured(case, "B", 1)
        self.assertTrue(row["proposed"])
        self.assertFalse(row["verified"])
        totals = score([row, dict(row, issue="tool unavailable")], "B")
        self.assertEqual((totals["TP"], totals["incomplete"], totals["n"]), (1, 1, 2))
        self.assertEqual(totals["fix_per_eligible"], 0)
        self.assertIsNone(totals["false_positive_rate"])
        self.assertIsNone(score([], "A")["fix_per_eligible"])
