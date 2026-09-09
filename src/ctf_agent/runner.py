from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import CTFError
from .runtime_lock import challenge_lock
from .scope import ScopeStore, ensure_network_command_safe, validate_network_command
from .state import StateStore
from .util import atomic_write_text, display_bytes, next_log_id, sha256_bytes, sha256_file, utcnow

SAFE_TAG_RE = re.compile(r"[^a-z0-9._-]+")

#: Seconds to wait after SIGTERM before escalating to SIGKILL.
TERM_GRACE_SECONDS = 5

#: Default cap for persisted stdout/stderr when the scope does not define one.
DEFAULT_MAX_OUTPUT_BYTES = 5_000_000


def safe_tag(tag: str) -> str:
    cleaned = SAFE_TAG_RE.sub("-", tag.strip().lower()).strip("-.")
    if not cleaned:
        raise CTFError("Tag must contain at least one alphanumeric character.")
    return cleaned[:80]


VOLATILE_ENV_KEYS = {"PWD", "OLDPWD", "SHLVL", "_"}


def referenced_file_hashes(command: list[str], cwd: str) -> dict[str, str]:
    """Hash challenge-local files referenced directly by the command."""
    root = Path(cwd).resolve()
    result: dict[str, str] = {}
    for argument in command:
        candidate = Path(argument).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            candidate = candidate.resolve()
            if root not in candidate.parents or not candidate.is_file():
                continue
            result[argument] = sha256_file(candidate)
        except OSError:
            continue
    return result


def command_hash(
    command: list[str],
    cwd: str,
    env_vars: dict[str, str] | None = None,
    input_file: Path | None = None,
    network: bool = False,
    target: str | None = None,
    port: int | None = None,
    timeout: float | None = None,
) -> str:
    """Hash everything that can change a command's observable result.

    Environment values, input-file contents, and challenge-local files named by
    the command are hashed, never logged. Network target/port and timeout are part
    of the identity so a cached local result can never be presented as the result
    for a different remote target or changed exploit script.
    """
    import hashlib

    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in VOLATILE_ENV_KEYS
    }
    environment.update(env_vars or {})
    payload = json.dumps(
        {
            "command": command,
            "cwd": cwd,
            "environment": environment,
            "input_file": str(input_file) if input_file else None,
            "input_file_sha256": sha256_file(input_file) if input_file else None,
            "referenced_files": referenced_file_hashes(command, cwd),
            "network": network,
            "target": target,
            "port": port,
            "timeout": timeout,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def existing_metadata(log_dir: Path, wanted_hash: str) -> dict[str, Any] | None:
    if not log_dir.is_dir():
        return None
    for path in sorted(log_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("command_hash") == wanted_hash:
            return data
    return None


def _max_output_bytes(challenge_dir: Path) -> int:
    """Output cap from `.scope.yaml` limits, falling back to the default."""
    scope_path = challenge_dir / ".scope.yaml"
    if not scope_path.is_file():
        return DEFAULT_MAX_OUTPUT_BYTES
    try:
        limits = ScopeStore(challenge_dir).load().get("limits") or {}
    except CTFError:
        return DEFAULT_MAX_OUTPUT_BYTES
    try:
        return int(limits.get("max_output_bytes") or DEFAULT_MAX_OUTPUT_BYTES)
    except (TypeError, ValueError):
        return DEFAULT_MAX_OUTPUT_BYTES


def _trim(data: bytes, limit: int) -> tuple[bytes, bool]:
    if limit <= 0 or len(data) <= limit:
        return data, False
    return data[:limit], True


def _terminate_process_group(proc: subprocess.Popen) -> str:
    """Terminate *proc*'s process group, escalating to SIGKILL after a grace period.

    Children are started with ``start_new_session=True`` so the command is a
    session/process-group leader; killing the group also reaps grandchildren.
    Returns the signal name used for the final kill.
    """
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=TERM_GRACE_SECONDS)
        return "SIGTERM"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        return "SIGKILL"


def _duration_ms(started_at: str, ended_at: str) -> int:
    start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    end = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
    return int((end - start).total_seconds() * 1000)


def run_command(
    challenge_dir: Path,
    command: list[str],
    tag: str,
    classification: str = "general",
    network: bool = False,
    target: str | None = None,
    port: int | None = None,
    timeout: float | None = None,
    force: bool = False,
    quiet: bool = False,
    print_limit: int = 20000,
    input_file: Path | None = None,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a command with complete logging.

    The whole operation (cache lookup, ID allocation, execution, metadata
    write, event append) runs under the challenge-level runtime lock so two
    agents cannot interleave log IDs or metadata on the same challenge.
    Children run in a dedicated process group; on timeout the whole group is
    terminated so no grandchild process survives.
    """
    challenge_dir = challenge_dir.resolve()
    with challenge_lock(challenge_dir, description=f"run_command:{tag}"):
        state = StateStore(challenge_dir)
        state.load()
        if input_file is not None and not input_file.is_file():
            raise CTFError(f"Input file not found: {input_file}")
        scope = ScopeStore(challenge_dir)
        ensure_network_command_safe(command, network, target)
        scope_result = None
        if network and target:
            scope_result = scope.check(target, port)
            validate_network_command(command, target, port, scope.check)
            state_data = state.load()
            state_data.setdefault("scope", {})["checked_at"] = scope_result["checked_at"]
            state.save(state_data)

        log_dir = challenge_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        tag = safe_tag(tag)
        cwd = str(challenge_dir)
        hash_value = command_hash(
            command,
            cwd,
            env_vars,
            input_file,
            network=network,
            target=target,
            port=port,
            timeout=timeout,
        )
        if not force:
            previous = existing_metadata(log_dir, hash_value)
            if previous:
                previous["cache_hit"] = True
                if not quiet:
                    print(
                        f"[skip] identical command already logged as {previous['id']} "
                        f"(use --force to rerun)",
                        flush=True,
                    )
                return previous

        log_id = next_log_id(log_dir)
        sequence = log_id.split("-")[1]
        base = f"{sequence}-{tag}"
        metadata_path = log_dir / f"{base}.json"
        stdout_path = log_dir / f"{base}.stdout"
        stderr_path = log_dir / f"{base}.stderr"

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        stdin_data = None
        if input_file is not None:
            stdin_data = input_file.read_bytes()

        max_output_bytes = _max_output_bytes(challenge_dir)
        started = utcnow()
        timed_out = False
        terminated: str | None = None
        error: str | None = None
        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
            try:
                stdout, stderr = proc.communicate(input=stdin_data, timeout=timeout)
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                terminated = _terminate_process_group(proc)
                stdout = proc.stdout.read() if proc.stdout else b""
                stderr = proc.stderr.read() if proc.stderr else b""
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()
                returncode = 124
                error = (
                    f"timeout after {timeout} seconds; "
                    f"process group terminated ({terminated})"
                )
        except FileNotFoundError as exc:
            stdout = b""
            stderr = str(exc).encode("utf-8")
            returncode = 127
            error = "command not found"
        except PermissionError as exc:
            stdout = b""
            stderr = str(exc).encode("utf-8")
            returncode = 126
            error = "permission denied"

        if stdout is None:
            stdout = b""
        if stderr is None:
            stderr = b""
        stdout_full_size = len(stdout)
        stderr_full_size = len(stderr)
        stdout, stdout_truncated = _trim(stdout, max_output_bytes)
        stderr, stderr_truncated = _trim(stderr, max_output_bytes)

        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        ended = utcnow()
        metadata: dict[str, Any] = {
            "id": log_id,
            "tag": tag,
            "class": classification,
            "command": command,
            "command_display": shlex.join(command),
            "command_hash": hash_value,
            "cwd": cwd,
            "input_file": str(input_file) if input_file else None,
            "started_at": started,
            "ended_at": ended,
            "duration_ms": _duration_ms(started, ended),
            "exit_code": returncode,
            "timed_out": timed_out,
            "terminated": terminated,
            "error": error,
            "stdout_file": str(stdout_path.relative_to(challenge_dir)),
            "stderr_file": str(stderr_path.relative_to(challenge_dir)),
            "stdout_size": len(stdout),
            "stderr_size": len(stderr),
            "stdout_full_size": stdout_full_size,
            "stderr_full_size": stderr_full_size,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "stdout_sha256": sha256_bytes(stdout),
            "stderr_sha256": sha256_bytes(stderr),
            "scope_check": scope_result,
        }
        atomic_write_text(metadata_path, json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
        state.event(
            "command_executed",
            {
                "log_id": log_id,
                "tag": tag,
                "class": classification,
                "command": command,
                "exit_code": returncode,
                "stdout_file": metadata["stdout_file"],
                "stderr_file": metadata["stderr_file"],
                "scope_check": scope_result,
            },
        )

        if not quiet:
            if stdout:
                print(
                    display_bytes(stdout, print_limit),
                    end="" if stdout.endswith(b"\n") else "\n",
                )
            if stderr:
                import sys

                print(
                    display_bytes(stderr, print_limit),
                    file=sys.stderr,
                    end="" if stderr.endswith(b"\n") else "\n",
                )
            print(
                json.dumps(
                    {
                        "id": log_id,
                        "exit_code": returncode,
                        "stdout_file": metadata["stdout_file"],
                        "stderr_file": metadata["stderr_file"],
                    },
                    ensure_ascii=False,
                )
            )
        return metadata


def run_tty(
    challenge_dir: Path,
    command: list[str],
    tag: str,
    classification: str = "interactive",
    network: bool = False,
    target: str | None = None,
    port: int | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Run an interactive command under script(1), preserving a transcript."""
    challenge_dir = challenge_dir.resolve()
    with challenge_lock(challenge_dir, description=f"run_tty:{tag}"):
        state = StateStore(challenge_dir)
        scope = ScopeStore(challenge_dir)
        ensure_network_command_safe(command, network, target)
        scope_result = None
        if network and target:
            scope_result = scope.check(target, port)
            validate_network_command(command, target, port, scope.check)
            state_data = state.load()
            state_data.setdefault("scope", {})["checked_at"] = scope_result["checked_at"]
            state.save(state_data)
        log_dir = challenge_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        tag = safe_tag(tag)
        log_id = next_log_id(log_dir)
        sequence = log_id.split("-")[1]
        base = f"{sequence}-{tag}"
        transcript = log_dir / f"{base}.transcript"
        metadata_path = log_dir / f"{base}.json"

        wrapped = ["script", "-qef", str(transcript), "-c", shlex.join(command)]
        started = utcnow()
        timed_out = False
        terminated: str | None = None
        error: str | None = None
        try:
            proc = subprocess.Popen(
                wrapped,
                cwd=challenge_dir,
                start_new_session=True,
            )
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminated = _terminate_process_group(proc)
                returncode = 124
                error = (
                    f"timeout after {timeout} seconds; "
                    f"process group terminated ({terminated})"
                )
        except FileNotFoundError:
            returncode = 127
            error = "command not found"
        except PermissionError:
            returncode = 126
            error = "permission denied"

        stdout_size = transcript.stat().st_size if transcript.exists() else 0
        ended = utcnow()
        metadata: dict[str, Any] = {
            "id": log_id,
            "tag": tag,
            "class": classification,
            "command": command,
            "command_display": shlex.join(command),
            "interactive": True,
            "cwd": str(challenge_dir),
            "started_at": started,
            "ended_at": ended,
            "duration_ms": _duration_ms(started, ended),
            "exit_code": returncode,
            "timed_out": timed_out,
            "terminated": terminated,
            "error": error,
            "transcript_file": (
                str(transcript.relative_to(challenge_dir)) if transcript.exists() else None
            ),
            "transcript_size": stdout_size,
            "scope_check": scope_result,
        }
        atomic_write_text(
            metadata_path,
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        )
        state.event("command_executed", metadata)
        return metadata
