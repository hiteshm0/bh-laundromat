"""CLI entry points for read-only review and fixture verification."""

import subprocess
import sys
import uuid
from pathlib import Path
import typer

from . import gate, history, proposal, sandbox, scenarios, service
from .snapshot import LIMIT, TOKEN, snapshot
from .commands import errors, output


def _banner() -> str:
    try:
        art = subprocess.run(
            ["figlet", "-f", "standard", "LAUNDROMAT"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        ).stdout
        colored = subprocess.run(
            ["lolcat"],
            input=art,
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        ).stdout
        if colored.strip():
            return colored
    except Exception:
        return typer.style("LAUNDROMAT", fg=typer.colors.CYAN, bold=True)
    return typer.style("LAUNDROMAT", fg=typer.colors.CYAN, bold=True)


def _intro():
    typer.echo(_banner(), color=True)
    typer.echo(typer.style("Local vulnerability review · repair · gate", fg=typer.colors.MAGENTA, italic=True), color=True)
    typer.echo("", color=True)
    typer.echo(typer.style("Scan local repositories for supply-chain, secret, injection, guard and", fg=typer.colors.WHITE), color=True)
    typer.echo(typer.style("dependency faults. Verify candidate repairs. Serve the review API.", fg=typer.colors.WHITE), color=True)
    typer.echo("", color=True)
    typer.echo(typer.style("Capabilities", fg=typer.colors.YELLOW, bold=True, underline=True), color=True)
    rows = [
        ("laundromat review <path>", "Inspect a file, directory, diff or refs"),
        ("laundromat --demo --scenario <scenario>", "Run a built-in synthetic fault scenario"),
        ("laundromat scan <repo>", "Synchronous snapshot scan"),
        ("laundromat serve [--port <port>]", "Serve the FastAPI review dashboard"),
        ("laundromat doctor", "Validate the local environment"),
        ("laundromat gate --repo .", "Evaluate the pre-push policy"),
    ]
    width = max(len(c) for c, _ in rows)
    for command, detail in rows:
        typer.echo("  " + typer.style(f"{command:<{width}}", fg=typer.colors.GREEN, bold=True) + typer.style(f"   {detail}", fg=typer.colors.WHITE), color=True)
    typer.echo("", color=True)
    typer.echo(typer.style("Quick start", fg=typer.colors.YELLOW, bold=True, underline=True), color=True)
    for step in ("laundromat doctor", "laundromat --demo", "laundromat review ."):
        typer.echo("  " + typer.style(step, fg=typer.colors.GREEN, bold=True), color=True)


def register(app):
    @app.callback(invoke_without_command=True)
    def main(
        ctx: typer.Context,
        demo: bool = typer.Option(False, "--demo"),
        scenario: str = typer.Option(None),
        machine: bool = typer.Option(False, "--json"),
        demo_history: bool = typer.Option(False, "--demo-history"),
    ):
        if (
            ctx.invoked_subcommand is None
            and not demo
            and not scenario
            and not machine
            and not demo_history
        ):
            if not machine:
                _intro()
            raise typer.Exit(0)
        if demo_history:
            token = history.LEDGER.set(history.demo_home())
            ctx.call_on_close(lambda: history.LEDGER.reset(token))
        if demo:
            if ctx.invoked_subcommand:
                raise typer.BadParameter("--demo runs independently")
            with errors(machine):
                rows = [scenarios.run(s, progress_callback=None if machine else typer.echo)
                        for s in ([scenario] if scenario else scenarios.SCENARIOS)]
                output(rows[0] if scenario else {"scenarios": rows}, machine)
        elif scenario or machine:
            raise typer.BadParameter("Use top-level --scenario and --json with --demo")

    @app.command()
    def doctor(strict: bool = False, machine: bool = typer.Option(False, "--json")):
        if strict:
            result=sandbox.run(sandbox.request("calibration"),mode="strict")
        else:
            import subprocess
            with errors(machine):
                version=subprocess.check_output(["node","--version"],timeout=5,text=True).strip()
                result=dict(property="local Node version",runtime="local compatibility",status="complete",observations={"version":version})
        output(result, machine)
        if result["status"] != "complete":
            raise typer.Exit(2)

    @app.command()
    def accept(scan_id: str, machine: bool = typer.Option(False, "--json")):
        with errors(machine):
            output(proposal.decide(scan_id, "accept"), machine)

    @app.command()
    def reject(scan_id: str, machine: bool = typer.Option(False, "--json")):
        with errors(machine):
            output(proposal.decide(scan_id, "reject"), machine)

    @app.command()
    def dismiss(
        scan_id: str,
        finding_id: str,
        actor: str = typer.Option(...),
        reason: str = typer.Option(...),
        false_positive: bool = typer.Option(False, "--false-positive"),
    ):
        with errors(False):
            history.dismiss(scan_id, finding_id, actor, reason, false_positive)

    @app.command("seed-demo-history")
    def seed(machine: bool = typer.Option(False, "--json")):
        with errors(machine):
            output(history.seed_demo_history(), machine)

    @app.command()
    def review(
        path: Path = typer.Argument(None),
        diff: str = typer.Option(None),
        repo: Path = typer.Option(Path(".")),
        category: str = typer.Option(None, "--class"),
        mode: str = typer.Option(None),
        baseline: str = typer.Option("template"),
        fmt: str = typer.Option("text", "--format"),
    ):
        """Inspect a directory, a single file, a bounded unified diff, or native pre-push refs on stdin."""
        machine = fmt == "json"
        progress = typer.echo if fmt == "text" else None
        with errors(machine):
            mode = mode or ("proposal" if diff else "snapshot")
            classes = {
                "secret",
                "injection",
                "query",
                "guard",
                "dependency",
                "supply-chain",
                "slopsquatting",
                "command",
                "prompt",
            }
            if (
                fmt not in ("json", "text")
                or mode not in ("proposal", "snapshot", "push")
                or category
                and category not in classes
            ):
                raise ValueError("Unknown format, review mode or class")
            if baseline not in ("A", "B", "split", "template"):
                raise ValueError("Unknown baseline")
            if mode == "push":
                if path or diff or category or baseline != "template":
                    raise ValueError(
                        "Push review requires native ref input and the complete policy"
                    )
                result = gate.decide(repo, "", sys.stdin.read())
                output(result, machine)
                if result["push_decision"]["action"] != "allow":
                    raise typer.Exit(1)
                return
            if bool(diff) != (mode == "proposal") or path and diff:
                raise ValueError(
                    "Proposal mode requires --diff and --repo. A path selects snapshot mode."
                )
            if path and repo != Path("."):
                raise ValueError("Use either PATH or --repo for a snapshot")
            if diff and not repo.is_dir():
                raise ValueError("--repo must be a directory")
            target = (path or repo).resolve(strict=True)
            folder = target if target.is_dir() else target.parent
            snap, files = snapshot(folder, None if target.is_dir() else [target.name])
            req = dict(
                snapshot=snap,
                scope=sorted(files),
                trigger="read-only " + mode,
                category=category,
                full_context=target.is_dir(),
            )
            if diff:
                if diff == "-":
                    raw = sys.stdin.buffer.read(LIMIT + 1)
                else:
                    with Path(diff).open("rb") as handle:
                        raw = handle.read(LIMIT + 1)
                new, paths = proposal.patched(files, raw)
                result = (
                    proposal.compare(req, files, new, paths, progress) if baseline == "template" else None
                )
                files = {n: new[n] for n in paths if n in new}
                req["scope"] = paths
            elif baseline == "template":
                sid = service.enqueue(
                    folder,
                    None if target.is_dir() else [target.name],
                    # A new CLI review observes the current registry and tool availability.
                    key=uuid.uuid4().hex,
                    trigger="read-only snapshot",
                    category=category,
                )
                service.work(sid, progress_callback=progress)
                result = history.detail(sid)
            if baseline != "template":
                from .experiment import arm

                result = arm(
                    baseline,
                    files,
                    {
                        n: TOKEN.sub("[redacted]", v.decode(errors="replace"))
                        for n, v in files.items()
                    },
                )
            result = {**req, **result}
            if category:
                allowed = {"command", "prompt", "query"} if category == "injection" else {category}
                result["findings"] = [f for f in result["findings"] if f["category"] in allowed]
                result["display_class"] = category
            output(result, machine)
            if result.get("status") == "incomplete":
                raise typer.Exit(2)
