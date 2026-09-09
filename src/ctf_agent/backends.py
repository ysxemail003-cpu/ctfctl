"""Model backend abstraction for the solver loop (docs/CAPABILITY_PLAN.md Phase B1).

A backend is a thin wrapper around a model CLI that turns a prompt into plain
text. The solver asks for a strict JSON action object inside that text, so
backends only need to return the model's final message.

Supported CLIs (detected on PATH):

- ``codex``: ``codex exec -o <file> <prompt>`` (the ``-o`` file receives the
  final message; avoids depending on JSONL event schemas).
- ``claude``: ``claude -p <prompt>`` (print mode).
- ``gemini``: ``gemini -p <prompt>`` (best effort; same print convention).

Availability is detected per call so a missing CLI is reported clearly instead
of failing mid-solve. Live model calls are the operator's explicit choice; the
solver loop itself is tested with a scripted/fake backend.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .errors import CTFError


class Backend(Protocol):
    name: str

    def available(self) -> bool:
        ...

    def complete(self, prompt: str, timeout: float) -> str:
        ...


@dataclass
class CliBackend:
    """Runs a model CLI subprocess and returns its final text output."""

    name: str
    binary: str
    cwd: Path | None = None

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _build_argv(self, prompt: str, out_file: Path | None = None) -> list[str]:
        if self.name == "codex":
            argv = ["codex", "exec"]
            if out_file is not None:
                argv += ["-o", str(out_file)]
            argv.append(prompt)
            return argv
        if self.name == "claude":
            return ["claude", "-p", prompt]
        if self.name == "gemini":
            return ["gemini", "-p", prompt]
        raise CTFError(f"Unsupported backend: {self.name}")

    def complete(self, prompt: str, timeout: float = 300.0) -> str:
        if not self.available():
            raise CTFError(
                f"Backend {self.name!r} requires the {self.binary!r} CLI, which is not on PATH."
            )
        if self.name == "codex":
            with tempfile.TemporaryDirectory(prefix="ctf-agent-codex-") as tmp:
                out_file = Path(tmp) / "last-message.txt"
                argv = self._build_argv(prompt, out_file)
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(self.cwd) if self.cwd else None,
                )
                if proc.returncode != 0:
                    raise CTFError(
                        f"codex exec failed (rc={proc.returncode}): {(proc.stderr or '')[-600:]}"
                    )
                if out_file.is_file():
                    return out_file.read_text(encoding="utf-8", errors="replace").strip()
                return (proc.stdout or "").strip()
        argv = self._build_argv(prompt)
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(self.cwd) if self.cwd else None,
        )
        if proc.returncode != 0:
            raise CTFError(
                f"{self.binary} failed (rc={proc.returncode}): {(proc.stderr or '')[-600:]}"
            )
        return (proc.stdout or "").strip()


def available_backends() -> list[str]:
    """Names of backends whose CLI is currently installed, in preference order."""
    order = [("codex", "codex"), ("claude", "claude"), ("gemini", "gemini")]
    return [name for name, binary in order if shutil.which(binary)]


def get_backend(name: str | None = None, cwd: Path | None = None) -> Backend:
    """Resolve a backend by name, or auto-pick the first installed one."""
    candidates = {
        "codex": CliBackend("codex", "codex", cwd=cwd),
        "claude": CliBackend("claude", "claude", cwd=cwd),
        "gemini": CliBackend("gemini", "gemini", cwd=cwd),
    }
    if name in (None, "auto", ""):
        for candidate in ("codex", "claude", "gemini"):
            if candidates[candidate].available():
                return candidates[candidate]
        raise CTFError("No model backend available: install codex, claude, or gemini on PATH.")
    if name not in candidates:
        raise CTFError(f"Unknown backend: {name}. Choose from codex, claude, gemini, or auto.")
    backend = candidates[name]
    if not backend.available():
        raise CTFError(f"Backend {name!r} is not available: {name!r} CLI is missing from PATH.")
    return backend
