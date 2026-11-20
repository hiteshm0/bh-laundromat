"""Install the checksum-pinned official release into the active environment."""

import hashlib
import io
import os
import platform
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

HASHES = {
    "darwin_arm64": "d942f3ad147250c9edbaab3fed9e482f98d3b59ba10ae97b8d75647e3ade492c",
    "darwin_x64": "edf5a507008b0d2ef4959575772772770586409c1f6f74dabf19cbe7ec341ced",
    "linux_x64": "a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb",
    "linux_arm64": "eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356",
}


def main():
    if sys.prefix == sys.base_prefix:
        raise SystemExit("Activate the project virtual environment first.")
    arch = {"x86_64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    target = f"{platform.system().lower()}_{arch}"
    if target not in HASHES:
        raise SystemExit("Install Gitleaks v8.28.0 for this platform.")
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_{target}.tar.gz"
    with urlopen(url, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != HASHES[target]:
        raise SystemExit("Gitleaks release checksum mismatch")
    dest = Path(sys.executable).parent / "gitleaks"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as tmp:
            tmp.write(archive.extractfile("gitleaks").read())
    os.chmod(tmp.name, 0o755)
    os.replace(tmp.name, dest)
    print(f"Installed Gitleaks 8.28.0 at {dest}")


if __name__ == "__main__":
    main()
