"""Concurrency tests for the challenge-level runtime lock."""
from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.runtime_lock import ChallengeLockError, challenge_lock


def test_challenge_lock_is_reentrant_in_process(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "lock", "misc", "AI_NATIVE", confirm_authorization=True)
    with challenge_lock(challenge):
        with challenge_lock(challenge):  # nested same-thread acquisition must not deadlock
            (challenge / "work").mkdir(exist_ok=True)
    assert (challenge / ".runtime.lock").is_file()


def test_challenge_lock_excludes_other_process(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "excl", "misc", "AI_NATIVE", confirm_authorization=True)
    ready = multiprocessing.Event()
    release = multiprocessing.Event()

    def holder() -> None:
        with challenge_lock(challenge, timeout=30):
            ready.set()
            release.wait(30)

    ctx = multiprocessing.get_context("fork")
    proc = ctx.Process(target=holder)
    proc.start()
    try:
        assert ready.wait(10), "holder process did not acquire the lock"
        with pytest.raises(ChallengeLockError):
            with challenge_lock(challenge, timeout=0.4):
                pass
    finally:
        release.set()
        proc.join(10)
    assert proc.exitcode == 0
    # After the other process releases the lock, this process can acquire it.
    with challenge_lock(challenge, timeout=5):
        pass


def test_release_without_acquire_raises(tmp_path: Path):
    from ctf_agent.runtime_lock import release

    challenge = init_challenge(tmp_path, "demo", "norelease", "misc", "AI_NATIVE", confirm_authorization=True)
    with pytest.raises(ChallengeLockError):
        release(challenge)


def test_concurrent_run_command_log_ids_are_unique(tmp_path: Path):
    """20 concurrent command executions produce 20 unique, parseable logs."""
    challenge = init_challenge(tmp_path, "demo", "conc", "misc", "AI_NATIVE", confirm_authorization=True)
    ctx = multiprocessing.get_context("fork")
    queue: multiprocessing.queues.Queue = ctx.Queue()

    def worker(tag: str, outq: multiprocessing.queues.Queue) -> None:
        from ctf_agent.runner import run_command

        for index in range(5):
            meta = run_command(
                challenge,
                ["printf", f"{tag}-{index}\n"],
                f"{tag}{index}",
                "concurrency",
                quiet=True,
                force=True,
            )
            outq.put(meta["id"])

    processes = [ctx.Process(target=worker, args=(f"p{number}", queue)) for number in range(4)]
    for proc in processes:
        proc.start()
    for proc in processes:
        proc.join(60)
    assert all(proc.exitcode == 0 for proc in processes), "concurrent workers failed"

    ids = [queue.get(timeout=5) for _ in range(20)]
    assert len(ids) == 20
    assert len(set(ids)) == 20, "duplicate LOG ids allocated under concurrency"

    metadata_files = sorted((challenge / "logs").glob("*.json"))
    assert len(metadata_files) == 20
    seen: set[str] = set()
    for path in metadata_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["id"].startswith("LOG-")
        assert data["id"] not in seen
        seen.add(data["id"])
    # stdout files referenced by metadata must exist and contain expected output
    for path in metadata_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        stdout_path = challenge / data["stdout_file"]
        assert stdout_path.is_file()
