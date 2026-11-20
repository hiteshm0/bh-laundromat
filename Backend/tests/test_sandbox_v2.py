import subprocess
import unittest
from unittest.mock import patch
from laundromat import sandbox


class Sandbox(unittest.TestCase):
    def attempt(self, fault=None):
        seen = []

        def docker(args, timeout, env=None):
            self.assertGreater(timeout, 0)
            seen.append(args)
            op = args[1]
            if op == fault:
                if op == "start":
                    raise subprocess.TimeoutExpired("docker start", 1)
                raise ValueError("fixture fault " + op)
            return {
                "image": b"image",
                "create": b"a" * 64,
                "start": b'{"stages":["fixture-install-stage","v22.21.0"]}',
                "rm": b"removed",
                "ps": b"",
            }[op]

        with patch.object(sandbox, "command", side_effect=docker):
            r = sandbox.run(sandbox.request("calibration"))
        return r, seen

    def test_success_and_isolation(self):
        r, calls = self.attempt()
        self.assertEqual((r["status"], r["cleanup_status"]), ("complete", "removed"))
        self.assertEqual(r["container_id"], "a" * 64)
        for arg in (
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--pids-limit=32",
            "--cpus=0.5",
            "--memory=128m",
            "65534:65534",
        ):
            self.assertIn(arg, calls[1])
        self.assertNotIn("-v", calls[1])

    def test_missing_image_or_daemon(self):
        r, calls = self.attempt("image")
        self.assertEqual(
            (r["status"], r["cleanup_status"], len(calls)),
            ("incomplete", "no container created", 1),
        )

    def test_deadline_and_teardown(self):
        r, calls = self.attempt("start")
        self.assertEqual((r["status"], r["cleanup_status"]), ("incomplete", "removed"))
        self.assertEqual([c[1] for c in calls][-2:], ["rm", "ps"])

    def test_failed_teardown(self):
        r, _ = self.attempt("rm")
        self.assertEqual((r["status"], r["cleanup_status"]), ("incomplete", "unconfirmed"))

    def test_suite_input_and_allowlist(self):
        for changes in (
            {"suite_digest": "0" * 64},
            {"test_id": "unlisted"},
            {"timeout": 31},
            {"version": 2},
            {"input_hashes": {"a": "b"}},
        ):
            with patch.object(sandbox, "command") as command:
                result = sandbox.run({**sandbox.request("calibration"), **changes})
                self.assertEqual(result["status"], "incomplete")
                command.assert_not_called()
        self.assertEqual(
            sandbox.run(sandbox.request("binding", b"unsupported"), b"unsupported")["status"],
            "incomplete",
        )
