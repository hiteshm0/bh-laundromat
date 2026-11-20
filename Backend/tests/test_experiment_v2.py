import unittest
from unittest.mock import patch
from laundromat import experiment, sandbox
from Research.evaluate import measured, score, CLASSES


class Comparison(unittest.TestCase):
    def test_failed_model_counts_and_off_class_prediction(self):
        case = dict(
            id="control",
            group="control",
            eligible=False,
            labels=[],
            files={"a.js": "export const title='amber';"},
        )
        with patch("laundromat.provider.role", side_effect=ValueError("offline")):
            row = measured(case, "split", 1)
        self.assertEqual(score([row], CLASSES)["completed"], 0)
        finding = dict(
            category="secret", path="a.js", line=1, property="literal", rationale="parser fixture"
        )
        with patch(
            "laundromat.provider.role", return_value={"findings": [finding], "candidate": None}
        ):
            row = measured(case, "B", 1)
        self.assertEqual(score([row], CLASSES)["FP"], 1)
        self.assertEqual(row["unexpected"], ["secret"])

    def test_roles_receive_separate_typed_inputs_and_blind_audit(self):
        path = "command.js"
        data = sandbox.owned_bytes("argv", "before")
        candidate = {"path": path, "source": sandbox.owned_bytes("argv", "after").decode()}
        finding = dict(
            category="command",
            path=path,
            line=1,
            property="argument vector",
            rationale="one command string",
        )
        seen = []

        def observation(test, source, progress_callback=None):
            # Parser/dispatch test. The strict integration run exercises the real observer.
            from laundromat import owned

            after = source == sandbox.owned_bytes(test, "after")
            return dict(
                status="pass" if after else "fail",
                observations=owned.EXPECTED[test] if after else {"calls": [["catalog amber"]]},
                duration_ms=1,
            )

        def role(name, artifact, trace):
            seen.append((name, artifact))
            return {
                "detect": {"findings": [finding]},
                "verify": {"test_id": "argv"},
                "fix": {"candidate": candidate},
            }[name]

        with (
            patch("laundromat.owned.observe", side_effect=observation),
            patch("laundromat.provider.role", side_effect=role),
        ):
            r = experiment.arm("split", {path: data}, {path: data.decode()})
        self.assertEqual([n for n, _ in seen], ["detect", "verify", "fix"])
        self.assertNotIn("proposed_files", seen[1][1])
        self.assertNotIn("candidates", seen[2][1])
        self.assertEqual(r["audits"][0]["verdict"], "verified")
        with (
            patch("laundromat.owned.observe", side_effect=observation),
            patch(
                "laundromat.provider.role",
                return_value={"findings": [finding], "candidate": candidate},
            ),
        ):
            b = experiment.arm("B", {path: data}, {path: data.decode()})
        self.assertEqual(b["audits"][0]["candidate_sha256"], r["audits"][0]["candidate_sha256"])
