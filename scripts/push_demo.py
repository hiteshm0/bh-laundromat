"""Exercise the installed hook on a disposable inventory repository and local bare remote."""

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import webbrowser
from contextlib import closing, suppress
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from threading import Thread

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from laundromat.gate import PROGRESS_LABELS

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/warehouse"
SOURCE = "inventory/stock.cjs"
BOUND = '  return db.prepare("SELECT sku FROM stock WHERE aisle = ? ORDER BY sku").all(aisle);'
ORIGINAL = (
    "  return db.prepare(`SELECT sku FROM stock WHERE aisle = '${aisle}' ORDER BY sku`).all();"
)
PHASES = {
    "prepare": "Preparing the demo repository",
    "baseline": "Pushing the clean starting commit",
    **PROGRESS_LABELS,
}


def stop_process_group(process, interrupt=signal.SIGTERM):
    with suppress(ProcessLookupError):
        os.killpg(process.pid, interrupt)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


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

    def push(self, *, allowed, refs=("main",), progress=None):
        def advertised():
            return self.git(
                "--git-dir=" + str(self.remote),
                "for-each-ref",
                "--format=%(refname) %(objectname)",
            )

        before = advertised()
        args = ("git", "push", "local", *refs)
        if progress is None:
            p = self.run(*args, check=False)
        else:
            p = self.push_with_progress(args, progress)
        match = re.search(r"pre-push · [a-z]+ · ([a-f0-9]{32})", p.stdout + p.stderr)
        if not match:
            raise RuntimeError("Missing hook receipt: " + (p.stdout + p.stderr)[-900:])
        receipt = self.cli("show", match[1])
        if (p.returncode == 0) != allowed:
            raise RuntimeError("Unexpected push outcome: " + str(receipt["push_decision"]))
        if not allowed and before != advertised():
            raise RuntimeError("Blocked push changed a remote ref")
        return receipt

    def push_with_progress(self, args, report):
        from laundromat.gate import PROGRESS_PREFIX

        output = []
        env = dict(self.env, LAUNDROMAT_PUSH_PROGRESS="1")
        with subprocess.Popen(
            args, cwd=self.repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", start_new_session=True,
        ) as process:
            def read_output():
                for line in process.stdout:
                    if line.startswith(PROGRESS_PREFIX):
                        stage = line.removeprefix(PROGRESS_PREFIX).strip()
                        if stage in PHASES:
                            report(stage)
                    else:
                        output.append(line)

            reader = Thread(target=read_output)
            reader.start()
            try:
                process.wait(timeout=180)
            except BaseException:
                stop_process_group(process, signal.SIGINT)
                raise
            finally:
                reader.join()
        return subprocess.CompletedProcess(args, process.returncode, "".join(output), "")


def print_diff(console, patch):
    for line in patch.splitlines():
        style = ""
        if line.startswith(("@@", "---", "+++")):
            style = "dim"
        elif line.startswith("+"):
            style = "green"
        elif line.startswith("-"):
            style = "red"
        console.print(line, style=style, soft_wrap=True)


def review_issue(receipt, stage):
    for item in receipt["push_reviews"]:
        for call in item.get("role_calls", []):
            if call.get("outcome") == "unavailable":
                return "The model provider was unavailable. Check its configuration and try again."
            if call.get("outcome") == "invalid":
                return "The model returned an unusable result. Try running the demo again."
    return {
        "original": "The original query check did not finish. Check that Docker is running.",
        "verify": "The suggested fix could not pass all verification checks.",
    }.get(stage, "The security review could not finish.")


def print_summary(console, demo, receipt, stage, elapsed):
    ready = receipt.get("proposal_ready")
    if not ready:
        console.print("Push blocked · Review incomplete", style="bold yellow")
        console.print(review_issue(receipt, stage))
        console.print("No verified fix is available.")
        return

    review = next(item for item in receipt["push_reviews"] if item.get("verified"))
    console.print(f"Push blocked · Fix verified in {elapsed:.1f}s", style="bold yellow")
    console.print(f"SQL injection risk in {review['path']}:{review['detect']['line']}", style="bold")
    console.print("The fix passes the aisle value separately from the SQL text.")
    console.print()
    console.print("Verified diff", style="bold")
    print_diff(console, review["patch"])
    console.print("Passed the parameter-binding, regression, and security checks.")

    console.print()
    console.print("Next step", style="bold")
    repo = shlex.quote(str(demo.repo))
    ledger = shlex.quote(os.path.relpath(demo.env["LAUNDROMAT_HOME"], demo.repo))
    if review["state"] == "staged":
        console.print("The fix is staged. Review it, then commit and push.")
        console.print(f"  git -C {repo} diff --cached", soft_wrap=True)
    else:
        if receipt.get("staging_issue"):
            console.print("Automatic staging was deferred. You can try approving the fix manually.")
        else:
            console.print("Awaiting your approval. Run these commands to stage and inspect the fix.")
        console.print(f"  cd {repo} &&", soft_wrap=True)
        console.print(f"  LAUNDROMAT_HOME={ledger} laundromat approve {receipt['id']} &&", soft_wrap=True)
        console.print("  git diff --cached")


def start_dashboard(demo, scan_id):
    log = demo.repo.parent / "dashboard.log"
    with socket.socket() as listener, log.open("w") as stream:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        fd = listener.fileno()
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "laundromat.api:app", "--fd", str(fd),
             "--workers", "1", "--no-access-log"],
            cwd=demo.repo, env=demo.env, stdin=subprocess.DEVNULL, stdout=stream,
            stderr=subprocess.STDOUT, pass_fds=(fd,), start_new_session=True,
        )

    path = f"/review/{scan_id}"
    deadline = time.monotonic() + 10
    try:
        while process.poll() is None and time.monotonic() < deadline:
            try:
                with closing(HTTPConnection("127.0.0.1", port, timeout=0.3)) as connection:
                    connection.request("GET", path)
                    status = connection.getresponse().status
            except (OSError, HTTPException):
                time.sleep(0.1)
                continue
            if status == 200:
                return f"http://127.0.0.1:{port}{path}", process.pid
            if status == 503:
                raise RuntimeError("Build the dashboard with npm run build --prefix Frontend.")
            break
        raise RuntimeError(f"The dashboard could not start. See {log}")
    except BaseException:
        stop_process_group(process)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["developer", "vibe-coder"], default="developer")
    parser.add_argument(
        "--mock-provider",
        action="store_true",
        help="Use the labelled test transport with real Git, scanners and Docker",
    )
    parser.add_argument("--dashboard", action="store_true", help="Open this run's dashboard in a browser")
    options = parser.parse_args()
    console = Console(highlight=False, markup=False)
    progress_console = Console(stderr=True, highlight=False, markup=False)
    interactive = progress_console.is_terminal
    started = time.monotonic()
    label = "a mock model provider"
    if not options.mock_provider:
        from laundromat import provider
        try:
            label = provider.configuration()[0]
        except ValueError as exc:
            parser.error(str(exc))
    console.print(f"Laundromat demo · {options.mode} mode", style="bold")
    console.print(f"Review provider · {label}", style="dim")
    if not interactive:
        console.print()

    stage = None
    try:
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}…"), TimeElapsedColumn(),
            console=progress_console, disable=not interactive, transient=True,
            redirect_stdout=False, redirect_stderr=False,
        ) as display:
            task = display.add_task("", total=None)

            def report(next_stage):
                nonlocal stage
                if next_stage == stage:
                    return
                stage = next_stage
                if interactive:
                    display.update(task, description=PHASES[stage], refresh=True)
                else:
                    progress_console.print(f"{PHASES[stage]}…")

            report("prepare")
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
            report("baseline")
            demo.push(allowed=True)
            demo.introduce()
            report("scan")
            receipt = demo.push(allowed=False, progress=report)
    except KeyboardInterrupt:
        progress_console.print("Demo cancelled.", style="yellow")
        raise SystemExit(130) from None
    except FileNotFoundError as exc:
        progress_console.print(f"Required command or file missing: {exc.filename}", style="red")
        raise SystemExit(1) from None
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError):
        progress_console.print(f"The demo stopped while {PHASES[stage].lower()}.", style="red")
        raise SystemExit(1) from None

    console.print()
    print_summary(console, demo, receipt, stage, time.monotonic() - started)
    if options.dashboard:
        try:
            url, pid = start_dashboard(demo, receipt["id"])
        except KeyboardInterrupt:
            progress_console.print("Dashboard launch cancelled.", style="yellow")
            raise SystemExit(130) from None
        except (OSError, RuntimeError) as exc:
            progress_console.print(str(exc), style="yellow")
        else:
            console.print()
            console.print(f"Dashboard · {url}", soft_wrap=True)
            console.print(f"Stop the dashboard with kill {pid}.", style="dim")
            with suppress(webbrowser.Error, OSError):
                webbrowser.open(url, new=2)
    if not receipt.get("proposal_ready"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
