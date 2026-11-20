"""Exercise a real capture, HTTP server and rendered deep link in a fresh browser profile."""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from unittest.mock import patch
from urllib.request import urlopen

from laundromat import capture, history, service
from laundromat.workspace import FIXTURE


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        repo = root / "repo"
        shutil.copytree(FIXTURE / "fixture", repo)
        os.environ.update(LAUNDROMAT_HOME=str(root / "ledger"), LAUNDROMAT_RUNTIME="local")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        api = subprocess.Popen(["laundromat", "serve", "--port", str(port)])
        errors = []
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    with urlopen(url, timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            ready = threading.Event()
            real_submit = history.submit
            ids = []

            def pause(*args, **kwargs):
                sid = real_submit(*args, **kwargs)
                ids.append(sid)
                ready.set()
                for _ in range(400):
                    if (root / "continue").exists():
                        return sid
                    time.sleep(0.1)
                raise RuntimeError("Timed out waiting for rendered pre-task record")

            def worker():
                try:
                    with patch.object(history, "submit", side_effect=pause):
                        sid = capture.capture(repo, "annotate-search", True)
                    service.work(sid)
                except Exception as exc:
                    errors.append(exc)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            if not ready.wait(10):
                raise RuntimeError("Capture did not start")
            browser = (
                os.getenv("CHROME_PATH")
                or shutil.which("google-chrome")
                or "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            )
            subprocess.run(
                [
                    "node",
                    Path(__file__).with_suffix(".mjs"),
                    browser,
                    root,
                    url + "/review/" + ids[0],
                ],
                check=True,
                timeout=70,
            )
            thread.join(10)
            if errors:
                raise errors[0]
            if history.detail(ids[0])["status"] != "findings":
                raise RuntimeError("Capture failed")
        finally:
            api.terminate()
            api.wait(10)


if __name__ == "__main__":
    main()
