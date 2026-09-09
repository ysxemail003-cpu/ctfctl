"""Query-index regressions: rebuild, corruption recovery, and 10k-log lookup."""
from __future__ import annotations

import json
import time
from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.logindex import (
    INDEX_FILENAME,
    ensure_current,
    lookup_by_hash,
    metadata_files,
    recent_summaries,
)
from ctf_agent.runner import run_command


def _challenge(tmp_path: Path, name: str = "index") -> Path:
    return init_challenge(tmp_path, "demo", name, "misc", "AI_NATIVE", confirm_authorization=True)


def test_runner_keeps_index_and_cache_still_works(tmp_path: Path):
    challenge = _challenge(tmp_path)
    first = run_command(challenge, ["printf", "hello\n"], "hello", "test", quiet=True)
    run_command(challenge, ["printf", "world\n"], "world", "test", quiet=True)
    index_path = challenge / "logs" / INDEX_FILENAME
    assert index_path.is_file()
    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["log_count"] == 2
    assert index["entries"][first["id"]]["command_hash"] == first["command_hash"]

    # Cache hit path still resolves through the index.
    cached = run_command(challenge, ["printf", "hello\n"], "hello", "test", quiet=True)
    assert cached["cache_hit"] is True
    assert cached["id"] == first["id"]


def test_index_rebuilds_after_corruption_or_loss(tmp_path: Path):
    challenge = _challenge(tmp_path)
    meta = run_command(challenge, ["printf", "x\n"], "x", "test", quiet=True)
    log_dir = challenge / "logs"
    index_path = log_dir / INDEX_FILENAME

    # Corrupt index -> lookup recovers by rebuilding.
    index_path.write_text("{ not json", encoding="utf-8")
    assert lookup_by_hash(log_dir, meta["command_hash"])["id"] == meta["id"]
    # Lost index -> lookup rebuilds.
    index_path.unlink()
    assert lookup_by_hash(log_dir, meta["command_hash"])["id"] == meta["id"]
    assert index_path.is_file()


def test_context_ignores_index_file(tmp_path: Path):
    from ctf_agent.context import build_context

    challenge = _challenge(tmp_path)
    log1 = run_command(challenge, ["printf", "a\n"], "a", "test", quiet=True)["id"]
    log2 = run_command(challenge, ["printf", "b\n"], "b", "test", quiet=True)["id"]
    context = build_context(challenge, max_logs=10)
    log_ids = [item["id"] for item in context["recent_logs"]]
    assert log_ids == [log1, log2]
    assert INDEX_FILENAME not in [Path(item["stdout_file"]).name for item in context["recent_logs"]]


def test_ten_thousand_logs_cache_lookup_is_fast(tmp_path: Path):
    challenge = _challenge(tmp_path)
    log_dir = challenge / "logs"
    for i in range(10_000):
        (log_dir / f"{i:06d}-bulk.json").write_text(
            json.dumps(
                {
                    "id": f"LOG-{i:06d}",
                    "tag": "bulk",
                    "command_hash": f"hash-{i:06d}",
                    "command": ["true"],
                }
            ),
            encoding="utf-8",
        )
    assert len(metadata_files(log_dir)) == 10_000

    started = time.monotonic()
    index = ensure_current(log_dir)
    build_seconds = time.monotonic() - started
    assert index["log_count"] == 10_000
    assert index["by_hash"]["hash-005000"] == "LOG-005000"

    started = time.monotonic()
    for i in (0, 5000, 9999):
        assert lookup_by_hash(log_dir, f"hash-{i:06d}")["id"] == f"LOG-{i:06d}"
    lookup_seconds = time.monotonic() - started
    # Generous bound: 10k logs, three index lookups, well under a second each.
    assert lookup_seconds < 3.0, f"lookup too slow: {lookup_seconds:.2f}s"
    assert build_seconds < 20.0, f"rebuild too slow: {build_seconds:.2f}s"

    summaries = recent_summaries(log_dir, 5)
    assert summaries[0]["id"] == "LOG-009999"
