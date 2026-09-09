"""Single source of truth for the ctf-agent version.

The version is maintained once in ``pyproject.toml``. Installed packages use
``importlib.metadata``; development checkouts fall back to reading
``pyproject.toml`` from the repository root.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("ctf-agent")
    except PackageNotFoundError:
        pass
    root = Path(__file__).resolve().parents[2]
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        import tomllib

        with pyproject.open("rb") as handle:
            data = tomllib.load(handle)
        project = data.get("project", {})
        if isinstance(project, dict) and isinstance(project.get("version"), str):
            return project["version"]
    return "0.0.0.dev0"
