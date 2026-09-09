"""Runner error paths: missing/permission-denied commands, tty, input policy."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError
from ctf_agent.runner import run_command, run_tty


def _challenge(tmp_path: Path, name: str = "runner-errors") -> Path:
    return init_challenge(tmp_path, "demo", name, "misc", "AI_NATIVE", confirm_authorization=True)


def test_run_command_not_found(tmp_path: Path):
    challenge = _challenge(tmp_path)
    meta = run_command(challenge, ["definitely-not-a-real-binary-xyz"], "missing", "test", quiet=True)
    assert meta["exit_code"] == 127
    assert meta["error"] == "command not found"


def test_run_command_permission_denied(tmp_path: Path):
    challenge = _challenge(tmp_path)
    script = challenge / "work" / "noexec.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    script.chmod(0o644)  # not executable
    meta = run_command(challenge, [str(script)], "noexec", "test", quiet=True)
    assert meta["exit_code"] == 126
    assert meta["error"] == "permission denied"


def test_run_command_rejects_external_input_file(tmp_path: Path):
    challenge = _challenge(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(CTFError) as excinfo:
        run_command(challenge, ["cat"], "bad-input", "test", quiet=True, input_file=outside)
    assert "input file" in str(excinfo.value).lower()


def test_run_tty_records_transcript(tmp_path: Path):
    challenge = _challenge(tmp_path)
    meta = run_tty(challenge, ["printf", "tty-hello\n"], "tty-hello", "test")
    assert meta["exit_code"] == 0
    assert meta["transcript_file"] is not None
    transcript = challenge / str(meta["transcript_file"])
    assert transcript.is_file()
    assert "tty-hello" in transcript.read_text(encoding="utf-8", errors="ignore")


def test_run_tty_timeout_terminates_process_group(tmp_path: Path):
    challenge = _challenge(tmp_path)
    meta = run_tty(
        challenge,
        ["python3", "-c", "import time; time.sleep(60)"],
        "tty-timeout",
        "test",
        timeout=1,
    )
    assert meta["timed_out"] is True
    assert meta["terminated"] in {"SIGTERM", "SIGKILL"}
    assert meta["exit_code"] == 124


def test_run_command_non_quiet_output_and_cache_skip(tmp_path: Path, capsys):
    challenge = _challenge(tmp_path, "runner-nonquiet")
    run_command(challenge, ["printf", "visible-output\n"], "show", "test")
    out = capsys.readouterr().out
    assert "visible-output" in out
    assert '"id"' in out
    run_command(challenge, ["printf", "visible-output\n"], "show", "test")
    out2 = capsys.readouterr().out
    assert "[skip]" in out2
