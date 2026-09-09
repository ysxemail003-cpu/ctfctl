"""Task lease lifecycle: start, heartbeat, takeover, release."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError
from ctf_agent.state import StateStore
from ctf_agent.tasks import (
    heartbeat,
    list_tasks,
    release_task,
    start_task,
    take_over,
)


def _challenge(tmp_path: Path) -> Path:
    return init_challenge(tmp_path, "demo", "tasks", "web", "AI_NATIVE", confirm_authorization=True)


def test_start_and_list_tasks(tmp_path: Path):
    challenge = _challenge(tmp_path)
    task = start_task(challenge, "ctf-agent-web", "Map HTTP routes", ttl_seconds=60)
    assert task["id"] == "TASK-0001"
    assert task["status"] == "RUNNING"
    assert task["agent"] == "ctf-agent-web"
    assert task["lease_until"] is not None

    tasks = list_tasks(challenge)
    assert len(tasks) == 1
    assert tasks[0]["id"] == "TASK-0001"
    state = StateStore(challenge).load()
    assert len(state["active_tasks"]) == 1

    events = [
        json.loads(line)
        for line in (challenge / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(item["type"] == "task_started" for item in events)


def test_heartbeat_extends_lease(tmp_path: Path):
    challenge = _challenge(tmp_path)
    task = start_task(challenge, "web-agent", "objective", ttl_seconds=60)
    updated = heartbeat(challenge, task["id"], "web-agent", ttl_seconds=120)
    assert updated["lease_until"] > task["lease_until"]
    # wrong agent cannot heartbeat
    with pytest.raises(CTFError):
        heartbeat(challenge, task["id"], "other-agent", ttl_seconds=60)


def test_takeover_only_after_lease_expiry(tmp_path: Path):
    challenge = _challenge(tmp_path)
    task = start_task(challenge, "agent-a", "objective", ttl_seconds=60)
    with pytest.raises(CTFError) as excinfo:
        take_over(challenge, task["id"], "agent-b", ttl_seconds=60)
    assert "still leased" in str(excinfo.value)

    # Simulate lease expiry by rewinding lease_until in canonical state.
    state_store = StateStore(challenge)
    data = state_store.load()
    data["active_tasks"][0]["lease_until"] = "2000-01-01T00:00:00Z"
    state_store.save(data)

    taken = take_over(challenge, task["id"], "agent-b", ttl_seconds=60)
    assert taken["agent"] == "agent-b"
    assert taken["status"] == "RUNNING"


def test_release_task_requires_running_and_terminal_outcome(tmp_path: Path):
    challenge = _challenge(tmp_path)
    task = start_task(challenge, "agent-a", "objective", ttl_seconds=60)
    with pytest.raises(CTFError):
        release_task(challenge, task["id"], outcome="MAYBE")
    released = release_task(challenge, task["id"], outcome="DONE")
    assert released["status"] == "DONE"
    assert released["ended_at"] is not None
    assert released["lease_until"] is None
    with pytest.raises(CTFError):
        release_task(challenge, task["id"], outcome="DONE")  # already released
    with pytest.raises(CTFError):
        release_task(challenge, "TASK-9999", outcome="DONE")  # unknown id
