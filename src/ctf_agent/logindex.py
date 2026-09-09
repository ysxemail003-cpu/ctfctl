"""Derived log query index (Phase 5 of OPTIMIZATION_PLAN.md).

Canonical command metadata lives in ``logs/NNNNNN-<tag>.json`` files.
``logs/index.json`` is a derived query index mapping ``LOG-*`` ids and command
hashes to metadata summaries so command-cache lookups stay fast with thousands
of logs. The index is disposable: when it is missing, stale, or corrupted it is
rebuilt from the canonical metadata files.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .util import atomic_write_text, utcnow

INDEX_VERSION = 1
INDEX_FILENAME = "index.json"

#: Fields kept in the index summary for each log metadata record.
SUMMARY_FIELDS = (
    "id",
    "tag",
    "class",
    "command",
    "command_display",
    "command_hash",
    "cwd",
    "exit_code",
    "timed_out",
    "error",
    "started_at",
    "ended_at",
    "duration_ms",
    "stdout_file",
    "stderr_file",
    "stdout_size",
    "stderr_size",
    "transcript_file",
    "scope_check",
)

_METADATA_NAME_RE = re.compile(r"^\d{6}-.*\.json$")


def metadata_files(log_dir: Path) -> list[Path]:
    """Canonical metadata files, excluding the derived index itself."""
    if not log_dir.is_dir():
        return []
    return sorted(path for path in log_dir.iterdir() if _METADATA_NAME_RE.match(path.name))


def _summarize(metadata: dict[str, Any]) -> dict[str, Any]:
    return {field: metadata.get(field) for field in SUMMARY_FIELDS if field in metadata}


def build(log_dir: Path) -> dict[str, Any]:
    """Scan canonical metadata files and build a fresh index."""
    entries: dict[str, dict[str, Any]] = {}
    by_hash: dict[str, str] = {}
    for path in metadata_files(log_dir):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        log_id = data.get("id")
        if isinstance(log_id, str) and log_id:
            entries[log_id] = _summarize(data)
        command_hash = data.get("command_hash")
        if isinstance(command_hash, str) and command_hash and isinstance(log_id, str):
            by_hash[command_hash] = log_id
    return {
        "version": INDEX_VERSION,
        "log_count": len(entries),
        "updated_at": utcnow(),
        "entries": entries,
        "by_hash": by_hash,
    }


def load(log_dir: Path) -> dict[str, Any] | None:
    """Load the index; return None when missing/invalid."""
    path = log_dir / INDEX_FILENAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("version") != INDEX_VERSION:
        return None
    if not isinstance(data.get("entries"), dict) or not isinstance(data.get("by_hash"), dict):
        return None
    return data


def save(log_dir: Path, index: dict[str, Any]) -> None:
    atomic_write_text(
        log_dir / INDEX_FILENAME,
        json.dumps(index, ensure_ascii=False, sort_keys=True) + "\n",
    )


def _is_current(index: dict[str, Any], log_dir: Path) -> bool:
    return int(index.get("log_count") or -1) == len(metadata_files(log_dir))


def ensure_current(log_dir: Path) -> dict[str, Any]:
    """Return a current index, rebuilding from canonical files when needed."""
    index = load(log_dir)
    if index is not None and _is_current(index, log_dir):
        return index
    fresh = build(log_dir)
    save(log_dir, fresh)
    return fresh


def update(log_dir: Path, metadata: dict[str, Any]) -> None:
    """Add/refresh one metadata record in the index (call under the lock).

    Loads the existing index (or builds once) and upserts a single entry so a
    burst of commands stays O(n) rather than forcing a full rebuild each time.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    index = load(log_dir)
    if index is None:
        index = build(log_dir)
    log_id = metadata.get("id")
    if isinstance(log_id, str) and log_id:
        index["entries"][log_id] = _summarize(metadata)
    command_hash = metadata.get("command_hash")
    if isinstance(command_hash, str) and command_hash and isinstance(log_id, str):
        index["by_hash"][command_hash] = log_id
    index["log_count"] = len(index["entries"])
    index["updated_at"] = utcnow()
    save(log_dir, index)


def lookup_by_hash(log_dir: Path, command_hash: str) -> dict[str, Any] | None:
    """Return the full metadata record for a command hash, or None."""
    index = ensure_current(log_dir)
    log_id = index.get("by_hash", {}).get(command_hash)
    if not isinstance(log_id, str) or not log_id:
        return None
    # The canonical metadata file is authoritative for full records.
    for path in metadata_files(log_dir):
        if path.name.startswith(log_id.split("-")[1] + "-"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if data.get("id") == log_id:
                return data
    return None


def recent_summaries(log_dir: Path, limit: int) -> list[dict[str, Any]]:
    """Newest-first metadata summaries (used by context rendering)."""
    index = ensure_current(log_dir)
    entries = index.get("entries", {})
    ordered = sorted(entries.values(), key=lambda item: str(item.get("id", "")), reverse=True)
    return ordered[:limit]
