"""Evidence-safe log archival and summaries (Phase 5 #5).

A log may be archived only when nothing references it: facts, hypotheses,
techniques, transitions, flag sources, evidence-ledger sources, and event
payloads all pin ``LOG-*`` ids. Referenced logs are never moved, so evidence
resolution and session replay stay intact. Archiving moves unreferenced
metadata plus its sidecar files into ``logs/archive/<YYYY-MM-DD>/``.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import CTFError
from .evidence import EvidenceLedger
from .logindex import metadata_files
from .runtime_lock import challenge_lock
from .state import StateStore
from .util import utcnow

LOG_ID_RE = re.compile(r"LOG-\d{6}")


def _referenced_ids(challenge_dir: Path) -> set[str]:
    referenced: set[str] = set()
    data = StateStore(challenge_dir).load()

    def collect(items: Any) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            for ref in item.get("evidence") or []:
                if isinstance(ref, str) and LOG_ID_RE.fullmatch(ref):
                    referenced.add(ref)

    collect(data.get("facts"))
    collect(data.get("hypotheses"))
    for outcome in (data.get("techniques") or {}).values():
        collect(outcome)

    flag = data.get("flag") or {}
    for ref in flag.get("source") or []:
        if isinstance(ref, str) and LOG_ID_RE.fullmatch(ref):
            referenced.add(ref)
    last_log = (flag.get("reproduction") or {}).get("last_log")
    if isinstance(last_log, str) and LOG_ID_RE.fullmatch(last_log):
        referenced.add(last_log)

    for record in EvidenceLedger(challenge_dir).records():
        source = record.get("source")
        if isinstance(source, str) and LOG_ID_RE.fullmatch(source):
            referenced.add(source)

    # Event payloads (e.g. state transitions) may pin log evidence too.
    events_path = challenge_dir / "events.jsonl"
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            payload = event.get("payload") if isinstance(event, dict) else None
            if not isinstance(payload, dict):
                continue
            for ref in payload.get("evidence") or []:
                if isinstance(ref, str) and LOG_ID_RE.fullmatch(ref):
                    referenced.add(ref)
    return referenced


def _archive_root(challenge_dir: Path) -> Path:
    return challenge_dir / "logs" / "archive" / datetime.now().strftime("%Y-%m-%d")


def _sidecar_candidates(metadata_path: Path) -> list[Path]:
    return [
        metadata_path.with_suffix(".stdout"),
        metadata_path.with_suffix(".stderr"),
        metadata_path.with_suffix(".transcript"),
    ]


def summary(challenge_dir: Path) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    log_dir = challenge_dir / "logs"
    total_size = 0
    by_class: dict[str, int] = {}
    by_tag: dict[str, int] = {}
    count = 0
    for path in metadata_files(log_dir):
        count += 1
        for sidecar in _sidecar_candidates(path):
            if sidecar.is_file():
                total_size += sidecar.stat().st_size
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        by_class[str(data.get("class") or "unknown")] = by_class.get(str(data.get("class") or "unknown"), 0) + 1
        by_tag[str(data.get("tag") or "unknown")] = by_tag.get(str(data.get("tag") or "unknown"), 0) + 1
    return {
        "schema_version": 1,
        "log_count": count,
        "total_bytes": total_size,
        "by_class": by_class,
        "by_tag": by_tag,
        "referenced_count": len(_referenced_ids(challenge_dir)),
        "generated_at": utcnow(),
    }


def plan_archive(challenge_dir: Path) -> dict[str, Any]:
    """Return which unreferenced metadata files could be archived (no-op)."""
    challenge_dir = challenge_dir.resolve()
    referenced = _referenced_ids(challenge_dir)
    candidates: list[dict[str, Any]] = []
    log_dir = challenge_dir / "logs"
    for path in metadata_files(log_dir):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        log_id = data.get("id")
        if isinstance(log_id, str) and log_id in referenced:
            continue
        candidates.append(
            {
                "id": log_id if isinstance(log_id, str) else path.stem,
                "metadata": str(path.relative_to(challenge_dir)),
                "sidecars": [
                    str(item.relative_to(challenge_dir))
                    for item in _sidecar_candidates(path)
                    if item.is_file()
                ],
            }
        )
    return {
        "schema_version": 1,
        "archive_dir": str(_archive_root(challenge_dir).relative_to(challenge_dir)),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "referenced_count": len(referenced),
    }


def archive_logs(
    challenge_dir: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Archive unreferenced logs (or preview with ``dry_run=True``)."""
    challenge_dir = challenge_dir.resolve()
    with challenge_lock(challenge_dir, description="log.archive"):
        plan = plan_archive(challenge_dir)
        moved: list[str] = []
        if not dry_run:
            archive_root = _archive_root(challenge_dir)
            archive_root.mkdir(parents=True, exist_ok=True)
            for candidate in plan["candidates"]:
                for relative in [candidate["metadata"], *candidate["sidecars"]]:
                    path = challenge_dir / relative
                    if not path.is_file():
                        continue
                    destination = archive_root / path.name
                    try:
                        os.replace(path, destination)
                    except OSError as exc:
                        raise CTFError(
                            f"Failed to archive {relative}: {exc}"
                        ) from exc
                    moved.append(str(destination.relative_to(challenge_dir)))
            # Drop archived entries from the query index immediately.
            from .logindex import build as build_index
            from .logindex import save as save_index

            log_dir = challenge_dir / "logs"
            save_index(log_dir, build_index(log_dir))
        return {
            "schema_version": 1,
            "dry_run": dry_run,
            "moved_count": len(plan["candidates"]) if not dry_run else 0,
            "moved": moved,
            "candidates": plan["candidates"] if dry_run else [],
            "archive_dir": plan["archive_dir"],
        }
