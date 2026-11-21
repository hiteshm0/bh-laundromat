import json
import os
import sys
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import capture as tasks
from . import gate as push
from . import history, legacy, repair, service
from .snapshot import TOKEN


@contextmanager
def errors(machine=True):
    try:
        yield
    except (ValueError, OSError, KeyError, TypeError) as exc:
        message = TOKEN.sub("[redacted]", str(exc))
        typer.echo(json.dumps({"status": "incomplete", "reason": message}) if machine else message)
        raise typer.Exit(2) from exc


@contextmanager
def review_spinner(machine, message="Preparing review…"):
    console = Console(stderr=True)
    if machine or not sys.stdout.isatty() or not console.is_terminal or console.is_dumb_terminal:
        yield None
        return
    with console.status(message) as status:
        yield status


@contextmanager
def push_progress(console, labels):
    interactive = console.is_terminal and not console.is_dumb_terminal
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}…"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=not interactive,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as display:
        task = display.add_task("", total=None) if interactive else None
        previous = None

        def report(stage):
            nonlocal previous
            if stage == previous:
                return
            previous = stage
            label = labels[stage]
            if task is None:
                console.print(f"{label}…")
            else:
                display.update(task, description=label, refresh=True)

        yield report


def print_diff(console, patch):
    if not console.is_terminal:
        console.print(patch, end="", markup=False, highlight=False, soft_wrap=True)
        return
    for line in patch.splitlines(keepends=True):
        style = ""
        if line.startswith(("@@", "---", "+++")):
            style = "dim"
        elif line.startswith("+"):
            style = "green"
        elif line.startswith("-"):
            style = "red"
        console.print(line, end="", style=style, markup=False, highlight=False, soft_wrap=True)


def output(value, machine, *, compact=False):
    if machine:
        typer.echo(history.encoded(value))
    elif "cases" in value or "scenarios" in value:
        for scenario in value.get("scenarios", [value]):
            typer.echo(scenario["scenario"])
            for case in scenario["cases"]:
                typer.echo(f"  {case['case']} · {case['status']}")
                for h in case["findings"]:
                    typer.echo("    " + h["explanation"])
                for r in case.get("repairs", []):
                    typer.echo(f"    {r['property']} · {r['verdict']}")
                for issue in case.get("issues", []):
                    typer.echo("    " + issue)
            if calibration := scenario.get("lifecycle_calibration"):
                typer.echo("  Independent lifecycle calibration · " + calibration["status"])
    elif "snapshot" in value and "findings" in value:
        checks = [
            f"{k} {v['status']}"
            for k, v in value.get("coverage", {}).items()
            if isinstance(v, dict) and v.get("status") not in (None, "outside scope")
        ]
        if checks:
            typer.echo("Coverage · " + ", ".join(checks))
        typer.echo(f"{value['trigger']} · {value['status']} · {value.get('id', '')}")
        if not compact:
            for limit in value.get("scope_limits", []):
                typer.echo(limit)
        for item in value.get("changes", []):
            typer.echo(f"{item['change']} {item['path']}\n{item['diff']}")
        for h in value["findings"]:
            typer.echo(
                f"{'Critical' if h.get('severity') == 'P1' else h.get('severity', 'Candidate')}  {h.get('path') or 'selected input'}:{h.get('line') or '—'}  {h.get('category')}  {h.get('explanation') or h.get('rationale', 'Pattern match')}"
            )
        if r := value.get("repair"):
            if compact:
                typer.echo(f"Repair suggestion · {r['property']} · {r['verdict']}")
            else:
                typer.echo(
                    f"{r['property']} · {r['verdict']} · {r['origin']} · {r['state']}\n{r['diff']}"
                )
            if r.get("after") and "binding" in r["after"]:
                typer.echo(
                    f"Parameter binding  {r['before']['binding']['status']} → {r['after']['binding']['status']}"
                )
            if r.get("model_issue"):
                typer.echo(r["model_issue"])
        if value.get("mode"):
            typer.echo("Repository mode · " + value["mode"])
        for item in value.get("push_reviews", []):
            typer.echo(f"{item['path']} · {item['state']} · {item.get('reason') or item.get('property', '')}")
            if item.get("working_tree_issue"):
                typer.echo(item["working_tree_issue"])
            if item.get("patch"):
                print_diff(Console(), item["patch"])
        if value.get("staging_issue"):
            typer.echo(value["staging_issue"])
        states = {r["state"] for r in value.get("push_reviews", [])}
        if value.get("proposal_ready") and "proposed" in states:
            proposals = [r for r in value["push_reviews"] if r["state"] == "proposed"]
            for p in proposals:
                command = "laundromat approve " + value["id"]
                if len(proposals) > 1:
                    command += " --finding " + p["finding_id"]
                typer.echo("Approve and stage with " + command)
        if "staged" in states:
            typer.echo("Review git diff --cached, commit the staged repair, then push again.")
        if (d := value.get("push_decision")) and (not compact or d["action"] != "not evaluated"):
            typer.echo(f"{d['action']} · {d['reason']}")
            for fid in d.get("pending", []):
                typer.echo(f"laundromat acknowledge {value['id']} {fid}")
        for reason in value.get("issues", []):
            typer.echo(reason)
        if compact and value.get("id"):
            typer.echo(f"Full receipt · laundromat show {value['id']}")
    else:
        typer.echo(TOKEN.sub("[redacted]", json.dumps(value, indent=2)))


def serve_dashboard(port, demo_root=None):
    import uvicorn

    # The server, its async tasks and to_thread workers inherit this context.
    token = history.LEDGER.set(demo_root or history.home())
    try:
        uvicorn.run("laundromat.api:app", host="127.0.0.1", port=port)
    finally:
        history.LEDGER.reset(token)


def register_commands(app):
    @app.command("apply-candidate")
    def apply_candidate(scan_id: str, finding_id: str, json_mode: bool = typer.Option(False, "--json")):
        """Apply a candidate repair after manually reviewing its diff."""
        with errors(json_mode):
            output(repair.apply_candidate_repair(scan_id, finding_id), json_mode)

    @app.command()
    def register(repo: Path, json_mode: bool = typer.Option(False, "--json")):
        """Allow the local API to scan this repository."""
        with errors(json_mode):
            path = str(repo.resolve(strict=True))
            if not repo.is_dir() or TOKEN.search(path):
                raise ValueError("Expected a local repository directory")
            with history.database() as db:
                db.execute("INSERT OR IGNORE INTO repositories VALUES(?)", (path,))
            output({"registered": path}, json_mode)

    @app.command()
    def scan(
        repo: Path,
        scope: list[str] = typer.Option(None, "--path"),
        key: str = typer.Option(None, "--key"),
        prepared: bool = False,
        model: bool = False,
        json_mode: bool = typer.Option(False, "--json"),
    ):
        """Scan local files synchronously and record the exact snapshot."""
        with errors(json_mode):
            with review_spinner(json_mode) as status:
                sid = service.enqueue(
                    repo,
                    scope or None,
                    key,
                    "prepared snapshot" if prepared else "local snapshot",
                    model,
                )
                service.work(sid, phase_callback=status.update if status else None)
                result = history.detail(sid)
            output(result, json_mode, compact=status is not None)
            if result["status"] in ("incomplete", "interrupted"):
                raise typer.Exit(2)

    @app.command()
    def capture(
        repo: Path,
        task: str,
        prepared: bool = False,
        proposal: bool = typer.Option(False, "--proposal"),
        auto_apply: bool = typer.Option(False, "--auto-apply"),
        timeout: int = typer.Option(60, min=1, max=180),
        json_mode: bool = typer.Option(False, "--json"),
    ):
        """Bound one Codex task, or replay the explicitly labeled prepared edit."""
        with errors(json_mode):
            sid = tasks.capture(repo, task, prepared, timeout, proposal, auto_apply)
            service.work(sid)
            result = history.detail(sid)
            output(result, json_mode)
            if result["status"] == "incomplete":
                raise typer.Exit(2)

    @app.command()
    def show(scan_id: str, json_mode: bool = typer.Option(False, "--json")):
        with errors(json_mode):
            output(history.detail(scan_id), json_mode)

    @app.command()
    def retry(scan_id: str, json_mode: bool = typer.Option(False, "--json")):
        with errors(json_mode):
            service.retry(scan_id)
            service.work(scan_id)
            result = history.detail(scan_id)
            output(result, json_mode)
            if result["status"] == "incomplete":
                raise typer.Exit(2)

    @app.command("import-receipt")
    def import_receipt(receipt: Path, json_mode: bool = typer.Option(False, "--json")):
        with errors(json_mode):
            output(history.detail(legacy.load(receipt)), json_mode)

    @app.command()
    def switch(setting: str):
        """Set the approval mode in this repository's local Git configuration."""
        with errors(False):
            typer.echo(push.mode(Path.cwd(), setting))

    @app.command()
    def mode(json_mode: bool = typer.Option(False, "--json")):
        """Print the effective repository mode."""
        with errors(json_mode):
            value = push.mode(Path.cwd())
            typer.echo(history.encoded({"mode": value}) if json_mode else value)

    @app.command()
    def approve(scan_id: str, finding: str = typer.Option(None, "--finding"), json_mode: bool = typer.Option(False, "--json")):
        """Stage a fresh, verified pre-push proposal in its reviewed worktree."""
        from . import push_stage

        with errors(json_mode):
            result = push_stage.apply(scan_id, finding=finding)
            typer.echo(history.encoded(result) if json_mode else result["next"])

    @app.command("install-hook")
    def install_hook(repo: Path, json_mode: bool = typer.Option(False, "--json")):
        with errors(json_mode):
            output(push.install(repo), json_mode)

    @app.command()
    def gate(
        repo: Path = typer.Option(Path(".")),
        remote: str = "",
        json_mode: bool = typer.Option(False, "--json"),
    ):
        started = time.monotonic()
        try:
            with errors(json_mode):
                stream_progress = not json_mode and os.getenv("LAUNDROMAT_PUSH_PROGRESS") == "1"
                console = Console(stderr=True, highlight=False, markup=False)
                interactive = not (json_mode or stream_progress) and (
                    console.is_terminal and not console.is_dumb_terminal
                )

                def emit(stage):
                    typer.echo(push.PROGRESS_PREFIX + stage, err=True)

                progress = (
                    push_progress(console, push.PROGRESS_LABELS) if interactive
                    else nullcontext(emit if stream_progress else None)
                )
                with progress as report:
                    result = push.decide(repo, remote, sys.stdin.read(), progress=report)
                output(result, json_mode, compact=interactive)
                if result["push_decision"]["action"] != "allow":
                    raise typer.Exit(1)
        finally:
            if not json_mode:
                elapsed_ms = round((time.monotonic() - started) * 1000)
                typer.echo(f"Pre-push elapsed · {elapsed_ms} ms")


    @app.command()
    def acknowledge(scan_id: str, finding_id: str, json_mode: bool = typer.Option(False, "--json")):
        with errors(json_mode):
            output(push.acknowledge(scan_id, finding_id), json_mode)

    @app.command()
    def serve(
        port: int = typer.Option(8731, min=1, max=65535),
        demo_history: bool = typer.Option(
            False, "--demo-history", help="Serve the pre-seeded demo replay ledger."
        ),
    ):
        """Start the local review API and dashboard."""
        with errors(False):
            root = history.demo_home() if demo_history else history.LEDGER.get()
            if root:
                if not (root / "history.sqlite").is_file():
                    typer.echo("Demo ledger not found. Run: laundromat seed-demo-history", err=True)
                    raise typer.Exit(2)
                typer.echo(f"Serving demo ledger from {root}")
            serve_dashboard(port, root)

    @app.command("demo-serve")
    def demo_serve(
        port: int = typer.Option(8731, min=1, max=65535),
        reseed: bool = typer.Option(False, "--reseed", help="Re-run the fixture checks before serving."),
    ):
        """Seed the demo ledger if needed and serve its dashboard."""
        with errors(False):
            root = history.demo_home()
            if reseed or not (root / "history.sqlite").is_file():
                typer.echo("Seeding demo history (this may take 1–3 minutes)...")
                result = history.seed_demo_history(reseed=reseed)
                typer.echo(f"Seeded {result['scans']} scans with {result['findings']} findings.")
                token = history.LEDGER.set(root)
                try:
                    for sid in result["injection_scan_ids"]:
                        if history.detail(sid)["repair"]:
                            typer.echo(f"  Injection scan: http://localhost:{port}/review/{sid}/repair")
                finally:
                    history.LEDGER.reset(token)
            typer.echo(f"Starting server at http://localhost:{port} (demo mode)")
            serve_dashboard(port, root)
