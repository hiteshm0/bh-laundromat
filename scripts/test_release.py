"""Build from the release allowlist and smoke-test the wheel in a fresh environment."""

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"


def run(*args, cwd, env=None):
    p = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=240)
    if p.returncode:
        raise RuntimeError(
            f"{Path(str(args[0])).name} exited {p.returncode}\n" + (p.stderr or p.stdout)[-1600:]
        )
    return p.stdout.strip()


def main():
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="laundromat-release-") as tmp:
        base = Path(tmp).resolve()
        source = base / "source"
        for name in (ROOT / "release-source.txt").read_text().splitlines():
            if not name or name.startswith("#"):
                continue
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        # Materialize only the intended resources, also supporting ordinary source archives.
        resources = source / "Backend/laundromat/assets"
        resources.mkdir(exist_ok=True)
        for name, where in (("demo", "demo"), ("rules", "Backend/rules")):
            shutil.copytree(source / where, resources / name)
        run("npm", "run", "build", "--prefix", "Frontend", cwd=ROOT)
        dist = ROOT / "Frontend/dist"
        dashboard = resources / "dashboard"
        dashboard.mkdir()
        page = (dist / "index.html").read_text()
        (dashboard / "index.html").write_text(page)
        assets = re.findall(r'(?:src|href)="/(assets/[\w.-]+\.(?:js|css))"', page)
        if not any(p.endswith(".js") for p in assets) or not any(
            p.endswith(".css") for p in assets
        ):
            raise ValueError("Dashboard build incomplete")
        (dashboard / "assets").mkdir()
        for asset in assets:
            shutil.copyfile(dist / asset, dashboard / asset)
        wheels = base / "wheel"
        run(
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "-w",
            wheels,
            source / "Backend",
            cwd=base,
        )
        (wheel,) = wheels.glob("*.whl")
        with zipfile.ZipFile(wheel) as z:
            contents = sorted(z.namelist())
            if any(
                re.search(
                    r"(?:^|/)(?:\.env|node_modules|\.git|.*\.sqlite|finish-project-prompt)", n
                )
                for n in contents
            ):
                raise ValueError("Unexpected wheel contents")
            expected = {
                str(p.relative_to(source / "Backend")) for p in resources.rglob("*") if p.is_file()
            }
            if expected - set(contents):
                raise ValueError(f"Missing wheel resources: {expected - set(contents)}")
        external = base / "unrelated"
        external.mkdir()
        install = base / "fresh"
        venv.EnvBuilder(with_pip=True).create(install)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")
        }
        env.update(
            PATH=str(install / "bin") + os.pathsep + os.environ["PATH"],
            LAUNDROMAT_HOME=str(base / "data"),
            LAUNDROMAT_RUNTIME=os.getenv("LAUNDROMAT_RUNTIME", "strict"),
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
        )
        py = install / "bin/python"
        run(py, "-m", "pip", "install", "--disable-pip-version-check", wheel, cwd=external, env=env)
        run(py, "-m", "pip", "check", cwd=external, env=env)
        module = run(
            py, "-c", "import laundromat;print(laundromat.__file__)", cwd=external, env=env
        )
        if not Path(module).is_relative_to(install):
            raise ValueError("Imported outside the clean venv")

        def cli(*args):
            return run(install / "bin/laundromat", *args, cwd=external, env=env)

        doctor = json.loads(cli("doctor", "--strict", "--json"))
        if doctor["status"] != "complete" or doctor["cleanup_status"] != "removed":
            raise ValueError("Strict calibration failed")
        cli("setup")
        target = base / "data/.laundromat/workspace/search.js"
        original = target.read_bytes()
        receipt = json.loads(cli("demo", "--json"))
        cli("apply", receipt["receipt"])
        cli("undo", receipt["receipt"])
        repo = external / "repo"
        shutil.copytree(target.parent, repo)
        run("git", "init", "-q", cwd=repo)
        h = json.loads(cli("install-hook", repo, "--json"))
        if not os.access(h["hook"], os.X_OK):
            raise ValueError("Hook missing")
        scan = json.loads(cli("scan", repo, "--json"))
        sid = scan["id"]
        applied = json.loads(cli("apply", sid, "--json"))
        restored = json.loads(cli("undo", sid, "--json"))
        if (
            restored["sha256"] != hashlib.sha256(original).hexdigest()
            or (repo / "search.js").read_bytes() != original
        ):
            raise ValueError("Rollback failed")
        bare = base / "remote.git"
        run("git", "init", "--bare", "-q", bare, cwd=base, env=env)
        # Exercise a clean push after the independent rollback check.
        shutil.copyfile(repo / "safe-search.js", repo / "search.js")
        run("git", "add", ".", cwd=repo, env=env)
        run(
            "git",
            "-c",
            "user.name=Release",
            "-c",
            "user.email=release@example.invalid",
            "commit",
            "-qm",
            "Synthetic fixture",
            cwd=repo,
            env=env,
        )
        run("git", "push", bare, "HEAD:refs/heads/review", cwd=repo, env=env)
        remote_tip = run("git", "rev-parse", "refs/heads/review", cwd=bare, env=env)
        if remote_tip != run("git", "rev-parse", "HEAD", cwd=repo, env=env):
            raise ValueError("Remote ref mismatch")
        scenario_results = json.loads(cli("--demo", "--json"))["scenarios"]
        summaries = {
            row["scenario"]: [
                {
                    "case": c["case"],
                    "status": c["status"],
                    "candidates": len(c["findings"]),
                    "verified": len(c["verified_actions"]),
                }
                for c in row["cases"]
            ]
            for row in scenario_results
        }
        if any(
            sum(c["verified"] for c in summaries[name]) < minimum
            for name, minimum in (("secret", 1), ("injection", 3), ("guard", 1), ("dependency", 1))
        ):
            raise ValueError("Expected owned property verification missing")
        if sum(c["candidates"] for c in summaries["supply-chain"]) != 1:
            raise ValueError("Structural control mismatch")
        seeded = json.loads(cli("seed-demo-history", "--json"))
        if seeded != json.loads(cli("seed-demo-history", "--json")) or seeded["findings"] < 20:
            raise ValueError("Historical replay count or idempotence failed")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        api = subprocess.Popen(
            [install / "bin/laundromat", "serve", "--port", str(port)], cwd=external, env=env
        )
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(120):
                try:
                    with urllib.request.urlopen(url + "/review/" + sid, timeout=1) as response:
                        html = response.read().decode()
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Dashboard did not start")
            for path in assets:
                if path not in html or not urllib.request.urlopen(url + "/" + path).read():
                    raise ValueError("Missing asset")
            detail = json.load(urllib.request.urlopen(url + "/scans/" + sid))
            if any(
                r["trigger"] == "demo replay"
                for r in json.load(urllib.request.urlopen(url + "/scans"))
            ):
                raise ValueError("Replay contaminated the normal ledger")
            if detail["repair"]["state"] != "restored":
                raise ValueError("Restored evidence missing")
        finally:
            api.terminate()
            api.wait(timeout=10)
        RELEASE.mkdir(exist_ok=True)
        shutil.copy2(wheel, RELEASE / wheel.name)
        report = dict(
            doctor=doctor,
            scenarios=summaries,
            demo_replay={k: v for k, v in seeded.items() if k != "ledger"},
            local_push_tip=remote_tip,
            wheel=wheel.name,
            sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
            contents=contents,
            original_sha256=restored["sha256"],
            applied_sha256=applied["sha256"],
            restored_sha256=restored["sha256"],
            runtime=env["LAUNDROMAT_RUNTIME"],
            dashboard_assets=assets,
            phase1=receipt["verdict"],
            installed_hook=Path(h["hook"]).name,
            elapsed_ms=round((time.monotonic() - start) * 1000),
        )
        (RELEASE / "wheel-contents.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            f"Passed clean installation, scan, receipt and ledger rollback, hook and dashboard · {len(contents)} wheel entries · {report['elapsed_ms']} ms"
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
