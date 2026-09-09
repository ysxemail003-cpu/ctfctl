"""Security regressions: path safety, original/ protection, redaction, budgets."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.redaction import (
    collect_secrets,
    marker_for,
    redact_env,
    redact_headers,
    redact_text,
)


def _challenge(tmp_path: Path, name: str) -> Path:
    return init_challenge(tmp_path, "demo", name, "misc", "AI_NATIVE", confirm_authorization=True)


def test_run_command_metadata_redacts_secret_env(tmp_path: Path):
    import json

    from ctf_agent.runner import run_command

    challenge = _challenge(tmp_path, "redact-run")
    meta = run_command(
        challenge,
        ["python3", "-c", "print('ran')", "leaky-secret-token-42"],
        "redact",
        "test",
        quiet=True,
        env_vars={"CTFD_TOKEN": "leaky-secret-token-42"},
    )
    assert meta["exit_code"] == 0
    blob = json.dumps(meta)
    assert "leaky-secret-token-42" not in blob
    sequence = meta["id"].split("-")[1]
    saved = json.loads(
        (challenge / "logs" / f"{sequence}-redact.json").read_text(encoding="utf-8")
    )
    assert "leaky-secret-token-42" not in json.dumps(saved)
    assert any("[REDACTED" in part for part in saved["command"])


# ---------------- path policy ----------------

def test_resolve_inside_rejects_dotdot_escape(tmp_path: Path):
    from ctf_agent.policy import PolicyError, resolve_inside

    challenge = _challenge(tmp_path, "dotdot")
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(PolicyError):
        resolve_inside(challenge, "../outside.txt")
    with pytest.raises(PolicyError):
        resolve_inside(challenge, "../../etc/passwd")
    # Normal challenge-local path resolves fine.
    assert resolve_inside(challenge, "work") == (challenge / "work").resolve()


def test_resolve_inside_rejects_symlink_escape(tmp_path: Path):
    from ctf_agent.policy import PolicyError, resolve_inside

    challenge = _challenge(tmp_path, "symlink")
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret", encoding="utf-8")
    (challenge / "work" / "link.txt").symlink_to(outside)
    with pytest.raises(PolicyError):
        resolve_inside(challenge, "work/link.txt")
    # A symlink pointing inside the challenge stays allowed.
    target = challenge / "work" / "real.txt"
    target.write_text("ok", encoding="utf-8")
    (challenge / "work" / "inside.txt").symlink_to(target)
    assert resolve_inside(challenge, "work/inside.txt") == target.resolve()


def test_ensure_not_original_blocks_original_writes(tmp_path: Path):
    from ctf_agent.policy import PolicyError, ensure_not_original

    challenge = _challenge(tmp_path, "original")
    (challenge / "original" / "input.bin").write_bytes(b"immutable")
    with pytest.raises(PolicyError):
        ensure_not_original(challenge, "original/input.bin")
    ensure_not_original(challenge, "work/out.txt")  # allowed


def test_ensure_inside_accepts_normal_paths(tmp_path: Path):
    from ctf_agent.policy import ensure_inside

    challenge = _challenge(tmp_path, "inside")
    ensure_inside(challenge, "logs")
    ensure_inside(challenge, challenge / "work")  # absolute form


# ---------------- budget policy ----------------

def test_budget_projection_and_limits(tmp_path: Path):
    from ctf_agent.policy import PolicyError, commit_usage, ensure_within_limits

    limits = {
        "max_requests": 10,
        "max_scan_ports": 100,
        "max_runtime_minutes": 1,
        "max_concurrent_commands": 2,
    }
    usage = {"requests": 5, "scan_ports": 20, "runtime_seconds": 30, "concurrent_commands": 0}
    projected = ensure_within_limits(limits, usage, {"requests": 2})
    assert projected["requests"] == 7
    with pytest.raises(PolicyError) as excinfo:
        ensure_within_limits(limits, usage, {"requests": 10})
    assert "max_requests" in str(excinfo.value)
    with pytest.raises(PolicyError):
        ensure_within_limits(limits, usage, {"runtime_seconds": 40})  # 70s > 60s
    with pytest.raises(PolicyError):
        ensure_within_limits(limits, usage, {"scan_ports": 90})  # 110 > 100
    new_usage = commit_usage(usage, {"requests": 3, "runtime_seconds": 10})
    assert new_usage["requests"] == 8
    assert new_usage["runtime_seconds"] == 40


# ---------------- redaction ----------------

def test_redact_env_and_secret_collection():
    env = {"CTFD_TOKEN": "super-secret-token", "PATH": "/usr/bin", "API_KEY": "abc123"}
    redacted = redact_env(env)
    assert "super-secret-token" not in str(redacted)
    assert "abc123" not in str(redacted)
    assert redacted["PATH"] == "/usr/bin"
    secrets = collect_secrets(env)
    assert "super-secret-token" in secrets
    assert "abc123" in secrets
    assert marker_for("super-secret-token").startswith("[REDACTED:")


def test_redact_headers():
    headers = {
        "Authorization": "Bearer tok-secret-1",
        "Cookie": "session=abc",
        "Content-Type": "application/json",
    }
    redacted = redact_headers(headers)
    assert "tok-secret-1" not in str(redacted)
    assert "session=abc" not in str(redacted)
    assert redacted["Content-Type"] == "application/json"


def test_redact_text_inline_patterns():
    text = "Authorization: Bearer tok-abc password=guessme token: xyz"
    out = redact_text(text)
    assert "tok-abc" not in out
    assert "guessme" not in out
    assert "xyz" not in out
    assert out.count("[REDACTED]") >= 3


def test_redact_text_replaces_known_secrets_deterministically():
    text = "connect with super-secret-token now"
    out = redact_text(text, ["super-secret-token"])
    assert "super-secret-token" not in out
    assert marker_for("super-secret-token") in out
    assert out == redact_text(text, ["super-secret-token"])
