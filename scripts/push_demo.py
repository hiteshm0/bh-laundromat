"""Exercise the installed hook on a disposable inventory repository and local bare remote."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import tempfile

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/warehouse"
SOURCE = "inventory/stock.cjs"
BOUND = '  return db.prepare("SELECT sku FROM stock WHERE aisle = ? ORDER BY sku").all(aisle);'
ORIGINAL = (
    "  return db.prepare(`SELECT sku FROM stock WHERE aisle = '${aisle}' ORDER BY sku`).all();"
)


class Rehearsal:
    def __init__(self, folder, env):
        self.repo = folder / "warehouse"
        self.remote = folder / "remote.git"
        self.env = {
            **env,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        shutil.copytree(EXAMPLE, self.repo)
        self.git("init", "--quiet", "-b", "main")
        self.git("config", "user.name", "Warehouse demo")
        self.git("config", "user.email", "warehouse@example.invalid")
        self.git("init", "--bare", "-q", "-b", "main", str(self.remote))
        self.git("remote", "add", "local", str(self.remote))
        self.cli("install-hook", ".")
        self.commit("Initial inventory service")

    def run(self, *args, check=True):
        return subprocess.run(
            args,
            cwd=self.repo,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=180,
            check=check,
        )

    def git(self, *args):
        return self.run("git", *args).stdout.strip()

    def cli(self, *args):
        return json.loads(self.run("laundromat", *args, "--json").stdout)

    def commit(self, msg):
        self.git("add", ".")
        self.git("commit", "-qm", msg)
        return self.git("rev-parse", "HEAD")

    def introduce(self):
        path = self.repo / SOURCE
        path.write_text(path.read_text().replace(BOUND, ORIGINAL))
        return self.commit("Change the aisle lookup")

    def push(self, *, allowed, refs=("main",)):
        def advertised():
            return self.git(
                "--git-dir=" + str(self.remote),
                "for-each-ref",
                "--format=%(refname) %(objectname)",
            )

        before = advertised()
        p = self.run("git", "push", "local", *refs, check=False)
        match = re.search(r"pre-push · [a-z]+ · ([a-f0-9]{32})", p.stdout + p.stderr)
        if not match:
            raise RuntimeError("Missing hook receipt: " + (p.stdout + p.stderr)[-900:])
        receipt = self.cli("show", match[1])
        if (p.returncode == 0) != allowed:
            raise RuntimeError("Unexpected push outcome: " + str(receipt["push_decision"]))
        if not allowed and before != advertised():
            raise RuntimeError("Blocked push changed a remote ref")
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["developer", "vibe-coder"], default="developer")
    parser.add_argument(
        "--mock-provider",
        action="store_true",
        help="Use the labelled test transport with real Git, scanners and Docker",
    )
    options = parser.parse_args()
    label = "mocked"
    if not options.mock_provider:
        from laundromat import provider
        try:
            label = provider.configuration()[0]
        except ValueError as exc:
            parser.error(str(exc))
    folder = Path(tempfile.mkdtemp(prefix="laundromat-push-"))
    env = dict(os.environ, LAUNDROMAT_HOME=str(folder / "ledger"))
    if options.mock_provider:
        transport = Path(__file__).resolve().parents[1] / "Backend/tests/push_fixtures"
        env.update(
            PYTHONPATH=str(transport),
            LAUNDROMAT_PROVIDER="openai",
            LAUNDROMAT_MODEL="mocked-push-test",
            OPENAI_API_KEY="local-mock-placeholder",
        )
    demo = Rehearsal(folder, env)
    demo.run("laundromat", "switch", options.mode)
    demo.push(allowed=True)
    demo.introduce()
    receipt = demo.push(allowed=False)
    print("Repository", demo.repo)
    print("Provider", label)
    prefix = "LAUNDROMAT_HOME=" + shlex.quote(env["LAUNDROMAT_HOME"])
    print("Dashboard command", prefix + " laundromat serve --port 8732")
    print("Review", "http://127.0.0.1:8732/review/" + receipt["id"])
    print(json.dumps(receipt["push_reviews"], indent=2))
    if not receipt.get("proposal_ready"):
        raise SystemExit("Review incomplete: " + str(receipt["issues"]))
    if options.mode == "developer":
        print("Approve with", prefix, "laundromat approve", receipt["id"])
    else:
        print(demo.git("diff", "--cached"))


if __name__ == "__main__":
    main()
