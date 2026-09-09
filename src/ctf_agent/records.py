"""Typed records for the runtime data model (Phase 5 of OPTIMIZATION_PLAN.md).

These TypedDicts document the canonical shapes of the main records the runtime
produces. They are deliberately ``total=False`` so older on-disk records that
lack newer optional fields remain compatible. Functional syntax is used so
keyword-named fields such as ``class`` are valid keys.
"""
from __future__ import annotations

from typing import Any, TypedDict

CommandMetadata = TypedDict(
    "CommandMetadata",
    {
        "id": str,
        "tag": str,
        "class": str,
        "command": list[str],
        "command_display": str,
        "command_hash": str,
        "cwd": str,
        "input_file": str | None,
        "started_at": str,
        "ended_at": str,
        "duration_ms": int,
        "exit_code": int,
        "timed_out": bool,
        "terminated": str | None,
        "error": str | None,
        "stdout_file": str,
        "stderr_file": str,
        "stdout_size": int,
        "stderr_size": int,
        "stdout_sha256": str,
        "stderr_sha256": str,
        "scope_check": dict[str, Any] | None,
        "transcript_file": str | None,
        "interactive": bool,
        "cache_hit": bool,
        "budget_error": str | None,
    },
    total=False,
)

EvidenceRecord = TypedDict(
    "EvidenceRecord",
    {
        "id": str,
        "source": str,
        "observation": str,
        "meaning": str,
        "classification": str,
        "confidence": str,
        "timestamp": str,
    },
    total=False,
)

AgentResult = TypedDict(
    "AgentResult",
    {
        "schema_version": int,
        "result_id": str,
        "agent": str,
        "status": str,
        "objective": str | None,
        "facts": list[dict[str, Any]],
        "hypotheses": list[dict[str, Any]],
        "failed_techniques": list[dict[str, Any]],
        "recommended_next_action": str,
        "source_hash": str,
        "risk": str | None,
        "confidence": str | None,
    },
    total=False,
)

LogIndexEntry = TypedDict(
    "LogIndexEntry",
    {
        "id": str,
        "tag": str,
        "command_hash": str,
        "command_display": str,
        "exit_code": int,
        "stdout_file": str,
        "stderr_file": str,
    },
    total=False,
)
