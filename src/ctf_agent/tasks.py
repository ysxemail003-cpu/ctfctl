"""Task leases for parallel specialist work (Phase 3 Task C).

Multiple low-concurrency agents may work on one challenge. A task lease gives a
single agent exclusive claim on a piece of work (e.g. "map HTTP routes") for a
bounded time. Expired leases can be taken over by another agent; every state
change is recorded as an event. State lives in ``state.yaml#active_tasks``.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .errors import CTFError
from .runtime_lock import challenge_lock
from .state import StateStore

TASK_RE = re.compile(r"^TASK-\d{4}$")
VALID_OUTCOMES = {"DONE", "CANCELLED", "FAILED", "ABANDONED"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _next_task_id(tasks: list[dict[str, Any]]) -> str:
    highest = 0
    for task in tasks:
        match = TASK_RE.match(str(task.get("id", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"TASK-{highest + 1:04d}"


def list_tasks(challenge_dir: Path) -> list[dict[str, Any]]:
    data = StateStore(challenge_dir).load()
    return list(data.get("active_tasks") or [])


def _find(data: dict[str, Any], task_id: str) -> dict[str, Any]:
    for task in data.get("active_tasks") or []:
        if task.get("id") == task_id:
            return task
    raise CTFError(f"Unknown task: {task_id}")


def start_task(
    challenge_dir: Path,
    agent: str,
    objective: str,
    ttl_seconds: int = 1800,
) -> dict[str, Any]:
    """Claim a new task lease for *agent*."""
    if not agent or not str(agent).strip():
        raise CTFError("A task agent is required.")
    if not objective or not str(objective).strip():
        raise CTFError("A task objective is required.")
    if ttl_seconds <= 0:
        raise CTFError("ttl_seconds must be positive.")
    challenge_dir = Path(challenge_dir).resolve()
    with challenge_lock(challenge_dir, description="task.start"):
        store = StateStore(challenge_dir)
        data = store.load()
        tasks = data.setdefault("active_tasks", [])
        now = _now()
        record = {
            "id": _next_task_id(tasks),
            "agent": agent,
            "objective": objective,
            "status": "RUNNING",
            "started_at": _iso(now),
            "lease_until": _iso(now + timedelta(seconds=ttl_seconds)),
            "heartbeat_at": _iso(now),
            "ended_at": None,
        }
        tasks.append(record)
        store.event("task_started", record)
        store.save(data)
    return record


def heartbeat(
    challenge_dir: Path,
    task_id: str,
    agent: str,
    ttl_seconds: int = 1800,
) -> dict[str, Any]:
    """Extend the lease of a RUNNING task owned by *agent*."""
    challenge_dir = Path(challenge_dir).resolve()
    with challenge_lock(challenge_dir, description="task.heartbeat"):
        store = StateStore(challenge_dir)
        data = store.load()
        task = _find(data, task_id)
        if task.get("status") != "RUNNING":
            raise CTFError(f"Task {task_id} is not RUNNING ({task.get('status')}).")
        if task.get("agent") != agent:
            raise CTFError(f"Task {task_id} is leased by {task.get('agent')}, not {agent}.")
        now = _now()
        task["heartbeat_at"] = _iso(now)
        task["lease_until"] = _iso(now + timedelta(seconds=ttl_seconds))
        store.event("task_heartbeat", task)
        store.save(data)
    return task


def take_over(
    challenge_dir: Path,
    task_id: str,
    new_agent: str,
    ttl_seconds: int = 1800,
) -> dict[str, Any]:
    """Take over an expired RUNNING lease; live leases are refused."""
    challenge_dir = Path(challenge_dir).resolve()
    with challenge_lock(challenge_dir, description="task.take_over"):
        store = StateStore(challenge_dir)
        data = store.load()
        task = _find(data, task_id)
        if task.get("status") != "RUNNING":
            raise CTFError(f"Task {task_id} is not RUNNING ({task.get('status')}).")
        lease_until = _parse_iso(task.get("lease_until"))
        if lease_until is not None and lease_until > _now():
            raise CTFError(
                f"Task {task_id} is still leased by {task.get('agent')} until "
                f"{task.get('lease_until')}; takeover not allowed."
            )
        now = _now()
        task["agent"] = new_agent
        task["lease_until"] = _iso(now + timedelta(seconds=ttl_seconds))
        task["heartbeat_at"] = _iso(now)
        store.event("task_taken_over", task)
        store.save(data)
    return task


def release_task(
    challenge_dir: Path,
    task_id: str,
    outcome: str = "CANCELLED",
) -> dict[str, Any]:
    """Release a RUNNING task with a terminal outcome."""
    outcome = outcome.upper()
    if outcome not in VALID_OUTCOMES:
        raise CTFError(f"Task outcome must be one of: {', '.join(sorted(VALID_OUTCOMES))}")
    challenge_dir = Path(challenge_dir).resolve()
    with challenge_lock(challenge_dir, description="task.release"):
        store = StateStore(challenge_dir)
        data = store.load()
        task = _find(data, task_id)
        if task.get("status") != "RUNNING":
            raise CTFError(f"Task {task_id} is not RUNNING ({task.get('status')}).")
        task["status"] = outcome
        task["ended_at"] = _iso(_now())
        task["lease_until"] = None
        store.event("task_released", task)
        store.save(data)
    return task
