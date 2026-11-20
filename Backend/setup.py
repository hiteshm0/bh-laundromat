"""Require the production UI when assembling a distributable wheel."""

from pathlib import Path
from setuptools import setup
from setuptools.command.build_py import build_py


class BuildResources(build_py):
    def run(self):
        assets = Path(__file__).resolve().parent / "laundromat/assets"
        if not (assets / "dashboard/index.html").is_file() or not list(
            (assets / "dashboard/assets").glob("*.js")
        ):
            raise RuntimeError("Build the dashboard first with npm run build --prefix Frontend")
        super().run()


setup(cmdclass={"build_py": BuildResources})
