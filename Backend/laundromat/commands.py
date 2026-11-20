import json
import sys
from contextlib import contextmanager
from pathlib import Path

import typer

from . import capture as tasks
from . import gate as push
from . import history, legacy, service
from .snapshot import TOKEN


@contextmanager
def errors(machine=True):
    try:
        yield
    except (ValueError, OSError, KeyError, TypeError) as exc:
        message = TOKEN.sub("[redacted]", str(exc))
        typer.echo(json.dumps({"status": "incomplete", "reason": message}) if machine else message)
        raise typer.Exit(2) from exc


def output(value, machine):
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
        for limit in value.get("scope_limits", []):
            typer.echo(limit)
        for item in value.get("changes", []):
            typer.echo(f"{item['change']} {item['path']}\n{item['diff']}")
        for h in value["findings"]:
            typer.echo(
                f"{'Critical' if h.get('severity') == 'P1' else h.get('severity', 'Candidate')}  {h.get('path') or 'selected input'}:{h.get('line') or '—'}  {h.get('category')}  {h.get('explanation') or h.get('rationale', 'Pattern match')}"
            )
        if r := value.get("repair"):
            typer.echo(
                f"{r['property']} · {r['verdict']} · {r['origin']} · {r['state']}\n{r['diff']}"
            )
            if r.get("after") and "binding" in r["after"]:
                typer.echo(
                    f"Parameter binding  {r['before']['binding']['status']} → {r['after']['binding']['status']}"
                )
            if r.get("model_issue"):
                typer.echo(r["model_issue"])
        if d := value.get("push_decision"):
            typer.echo(f"{d['action']} · {d['reason']}")
            for fid in d.get("pending", []):
                typer.echo(f"laundromat acknowledge {value['id']} {fid}")
        for reason in value.get("issues", []):
            typer.echo(reason)
    else:
        typer.echo(TOKEN.sub("[redacted]", json.dumps(value, indent=2)))


def register_commands(app):
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
            sid = service.enqueue(
                repo,
                scope or None,
                key,
                "prepared snapshot" if prepared else "local snapshot",
                model,
            )
            service.work(sid)
            result = history.detail(sid)
            output(result, json_mode)
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
        with errors(json_mode):
            result = push.decide(repo, remote, sys.stdin.read())
            output(result, json_mode)
            if result["push_decision"]["action"] != "allow":
                raise typer.Exit(1)

    @app.command()
    def acknowledge(scan_id: str, finding_id: str, json_mode: bool = typer.Option(False, "--json")):
        with errors(json_mode):
            output(push.acknowledge(scan_id, finding_id), json_mode)

    @app.command()
    def serve(port: int = typer.Option(8731, min=1, max=65535)):
        import uvicorn

        uvicorn.run("laundromat.api:app", host="127.0.0.1", port=port, log_level="warning")
