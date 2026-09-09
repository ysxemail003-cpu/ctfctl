"""Backend abstraction tests (no live model calls)."""
from __future__ import annotations

from pathlib import Path

import types

import pytest

from ctf_agent import backends as backends_module
from ctf_agent.errors import CTFError


def test_build_argv_codex(tmp_path):
    backend = backends_module.CliBackend("codex", "codex")
    argv = backend._build_argv("hello", tmp_path / "out.txt")
    assert argv[0] == "codex"
    assert "-o" in argv
    assert str(tmp_path / "out.txt") in argv
    assert "hello" in argv


def test_build_argv_claude_and_gemini():
    claude = backends_module.CliBackend("claude", "claude")._build_argv("hi")
    assert claude == ["claude", "-p", "hi"]
    gemini = backends_module.CliBackend("gemini", "gemini")._build_argv("hi")
    assert gemini == ["gemini", "-p", "hi"]


def test_get_backend_unknown_name():
    with pytest.raises(CTFError):
        backends_module.get_backend("not-a-backend")


def test_get_backend_reports_missing_auto(monkeypatch):
    monkeypatch.setattr(backends_module.shutil, "which", lambda name: None)
    with pytest.raises(CTFError, match="No model backend available"):
        backends_module.get_backend("auto")


def test_get_backend_reports_missing_named(monkeypatch):
    monkeypatch.setattr(backends_module.shutil, "which", lambda name: None)
    with pytest.raises(CTFError, match="not available"):
        backends_module.get_backend("codex")


def test_available_backends_filters(monkeypatch):
    installed = {"codex", "claude"}
    monkeypatch.setattr(backends_module.shutil, "which", lambda name: f"/usr/bin/{name}" if name in installed else None)
    assert backends_module.available_backends() == ["codex", "claude"]


def test_cli_backend_complete_missing_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(backends_module.shutil, "which", lambda name: None)
    backend = backends_module.CliBackend("codex", "codex", cwd=tmp_path)
    with pytest.raises(CTFError, match="not on PATH"):
        backend.complete("prompt", timeout=5)


def _fake_subprocess_factory(monkeypatch, codex_reply: str = "codex-reply", claude_reply: str = "claude-reply", rc: int = 0):
    # Pretend every CLI is installed so availability checks pass without host tools.
    monkeypatch.setattr(backends_module.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run(argv, **kwargs):
        if argv[0] == "codex":
            out_file = argv[argv.index("-o") + 1]
            Path(out_file).write_text(codex_reply, encoding="utf-8")
            return types.SimpleNamespace(returncode=rc, stdout="", stderr="boom" if rc else "")
        return types.SimpleNamespace(returncode=rc, stdout=claude_reply if not rc else "", stderr="boom" if rc else "")

    monkeypatch.setattr(backends_module.subprocess, "run", fake_run)


def test_codex_complete_reads_last_message_file(tmp_path, monkeypatch):
    _fake_subprocess_factory(monkeypatch)
    backend = backends_module.CliBackend("codex", "codex", cwd=tmp_path)
    assert backend.complete("prompt", timeout=10) == "codex-reply"


def test_claude_complete_returns_stdout(tmp_path, monkeypatch):
    _fake_subprocess_factory(monkeypatch)
    backend = backends_module.CliBackend("claude", "claude", cwd=tmp_path)
    assert backend.complete("prompt", timeout=10) == "claude-reply"


def test_complete_raises_on_nonzero_exit(tmp_path, monkeypatch):
    _fake_subprocess_factory(monkeypatch, rc=1)
    backend = backends_module.CliBackend("claude", "claude", cwd=tmp_path)
    with pytest.raises(CTFError, match="failed"):
        backend.complete("prompt", timeout=10)
