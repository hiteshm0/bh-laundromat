import json
import shlex
import re
from contextlib import contextmanager
from pathlib import Path

import typer

from . import review, workspace
from .commands import register_commands
from .snapshot import TOKEN
from . import repair

app = typer.Typer(
    no_args_is_help=True, help="Review a local search repair against the Phase 1 fixture."
)
register_commands(app)
from .public import register

register(app)


@contextmanager
def command(*, json_output=False):
    try:
        with workspace.workspace_lock():
            yield
    except (OSError, ValueError, KeyError, TypeError) as exc:
        if json_output:
            typer.echo(
                json.dumps({"verdict": "incomplete", "reason": TOKEN.sub("[redacted]", str(exc))})
            )
        else:
            typer.echo(TOKEN.sub("[redacted]", str(exc)), err=True)
        raise typer.Exit(2) from exc


@app.command()
def setup():
    """Create the disposable workspace if needed."""
    with command():
        workspace.setup(reset=False)
    typer.echo(f"Workspace ready at {workspace.WORK}")


@app.command()
def reset():
    """Recreate the marked disposable workspace, including its review history."""
    with command():
        workspace.setup(reset=True)
    typer.echo(f"Restored fixture at {workspace.WORK}")


def column(phase):
    if phase is None:
        return {}
    scan = phase["semgrep"]
    values = {
        "Semgrep findings": str(len(scan["findings"]))
        if scan["status"] == "complete"
        else scan["status"],
        "Safe control clean": scan.get("negative_control", "incomplete"),
        "Parameter binding": phase["binding"]["status"],
        "SQLite row IDs": phase["sqlite"]["status"],
    }
    for row in phase["sqlite"].get("results", []):
        values[f"  {row['term']}"] = str(row["actual"])
    return values


def show(receipt):
    if finding := receipt["finding"]:
        typer.echo(f"{finding['file']}:{finding['line']}  {finding['rule_id']}")
        typer.echo(finding["message"])
        typer.echo(f"Scanned SHA-256  {finding['scanned_sha256']}")
    before = column(receipt["before"])
    after = column(receipt["after"])
    typer.echo(f"\n{'Check':<22} {'Before':<15} After")
    for key in dict.fromkeys([*before, *after]):
        typer.echo(f"{key:<22} {before.get(key, '—'):<15} {after.get(key, '—')}")
    path = workspace.ROOT / receipt["receipt"]
    if receipt["repair"]:
        typer.echo("\nCandidate diff (template)")
        typer.echo((path.parent / "repair.diff").read_text(), nl=False)
    typer.echo(f"\n{receipt['verdict'].upper()}  ({receipt['elapsed_ms']} ms)")
    if receipt["reason"]:
        typer.echo(receipt["reason"])
    typer.echo(f"Receipt  {receipt['receipt']}")
    if receipt["verdict"] == "verified":
        typer.echo(f"Apply    laundromat apply {shlex.quote(str(path))}")


@app.command()
def demo(
    json_output: bool = typer.Option(False, "--json", help="Print the complete receipt as JSON."),
):
    """Scan and check a candidate copy. Leave the workspace source untouched."""
    with command(json_output=json_output):
        receipt = review.review()
        if json_output:
            typer.echo(workspace.json_bytes(receipt).decode(), nl=False)
        else:
            show(receipt)
    raise typer.Exit({"verified": 0, "unverified": 1, "incomplete": 2}[receipt["verdict"]])


@app.command()
def apply(
    receipt: Path,
    finding: str = typer.Option(None, "--finding"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Apply the verified candidate from RECEIPT to the disposable search file."""
    with command(json_output=json_output):
        if re.fullmatch(r"[0-9a-f]{32}", str(receipt)):
            typer.echo(json.dumps(repair.change(str(receipt), False, finding)))
            return
        review.change(receipt, undo=False)
    typer.echo(
        json.dumps({"state": "applied"})
        if json_output
        else f"Applied to {workspace.WORK / workspace.SEARCH}"
    )


@app.command()
def undo(
    receipt: Path,
    finding: str = typer.Option(None, "--finding"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Restore the original bytes saved when RECEIPT was applied."""
    with command(json_output=json_output):
        if re.fullmatch(r"[0-9a-f]{32}", str(receipt)):
            typer.echo(json.dumps(repair.change(str(receipt), True, finding)))
            return
        review.change(receipt, undo=True)
    typer.echo(
        json.dumps({"state": "restored"})
        if json_output
        else f"Restored {workspace.WORK / workspace.SEARCH}"
    )
