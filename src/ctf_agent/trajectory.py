"""Trajectory export (docs/CAPABILITY_PLAN.md Phase D2).

Aggregates a challenge's whole audit trail — logged commands, evidence ledger,
agent rounds and flag record — into a machine-loadable trajectory JSON (aligned
with the CSAW Agentic-CTF submission shape: thoughts / actions / observations /
final flag) plus a human-readable Markdown sidecar.

Only already-redacted stored data is used (runner metadata stores redacted
commands; raw secrets are never re-printed here). Credential values are never
included because the runtime never stores them in the first place.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import CTFError
from .state import StateStore
from .util import atomic_write_text, utcnow

LOG_SEQUENCE = re.compile(r"^(\d+)-")
SCHEMA_VERSION = 1


def _load_log_actions(challenge_dir: Path, limit: int = 2000) -> list[dict[str, Any]]:
    log_dir = challenge_dir / "logs"
    if not log_dir.is_dir():
        return []
    actions: list[dict[str, Any]] = []
    for path in sorted(log_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        match = LOG_SEQUENCE.match(path.name)
        if not match:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        actions.append(
            {
                "kind": "action",
                "sequence": int(match.group(1)),
                "log": str(data.get("id", path.stem)),
                "command": str(data.get("command_display") or data.get("command") or ""),
                "tag": str(data.get("tag", "")),
                "class": str(data.get("class", "")),
                "exit_code": data.get("exit_code"),
                "duration_ms": data.get("duration_ms"),
                "stdout_ref": data.get("stdout_file"),
                "stderr_ref": data.get("stderr_file"),
                "stdout_sha256": data.get("stdout_sha256"),
                "timed_out": bool(data.get("timed_out")),
            }
        )
    actions.sort(key=lambda item: item["sequence"])
    return actions[-limit:]


def _load_agent_rounds(challenge_dir: Path) -> list[dict[str, Any]]:
    rounds_dir = challenge_dir / "agent_rounds"
    if not rounds_dir.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(rounds_dir.glob("round-*/record.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        records.append(
            {
                "kind": "agent_round",
                "round": record.get("round"),
                "thought": str(record.get("analysis", ""))[:4000],
                "actions": record.get("executed", []),
                "flag_candidate": record.get("flag_candidate"),
            }
        )
    records.sort(key=lambda item: int(item.get("round") or 0))
    return records


def _load_evidence(challenge_dir: Path) -> list[dict[str, Any]]:
    path = challenge_dir / "evidence.jsonl"
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append(
            {
                "kind": "evidence",
                "id": str(item.get("id", "")),
                "source": str(item.get("source", "")),
                "observation": str(item.get("observation", ""))[:2000],
                "meaning": str(item.get("meaning", "")),
                "classification": str(item.get("classification", "")),
            }
        )
    return records


def export_trajectory(challenge_dir: Path) -> dict[str, Any]:
    """Build and persist the trajectory for one challenge; returns the record."""
    challenge_dir = challenge_dir.resolve()
    if not (challenge_dir / "state.yaml").is_file():
        raise CTFError(f"Not a challenge directory (missing state.yaml): {challenge_dir}")
    state = StateStore(challenge_dir).load()
    meta = state.get("challenge") or {}
    flag = state.get("flag") or {}

    actions = _load_log_actions(challenge_dir)
    rounds = _load_agent_rounds(challenge_dir)
    evidence = _load_evidence(challenge_dir)
    trajectory: list[dict[str, Any]] = actions + rounds + evidence
    trajectory.sort(key=lambda item: (item.get("sequence", 0), item.get("round", 0), item.get("kind", "")))

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow(),
        "challenge": {
            "name": str(meta.get("name", challenge_dir.name)),
            "event": str(meta.get("event", "")),
            "category": str(meta.get("category", "")),
            "mode": str(meta.get("mode", "")),
        },
        "status": str(state.get("status", "INIT")),
        "verdict": "SOLVED" if str(flag.get("status", "NONE")) in ("REPRODUCED", "ACCEPTED", "SUBMITTED") else str(flag.get("status", "NONE")),
        "final_flag": flag.get("value"),
        "flag_reproduction": flag.get("reproduction"),
        "summary": {
            "action_count": len(actions),
            "agent_round_count": len(rounds),
            "evidence_count": len(evidence),
            "event_count": len([line for line in (challenge_dir / "events.jsonl").read_text().splitlines() if line.strip()])
            if (challenge_dir / "events.jsonl").is_file()
            else 0,
        },
        "trajectory": trajectory,
    }

    reports_dir = challenge_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    name = str(meta.get("name", challenge_dir.name))
    json_path = reports_dir / f"trajectory-{name}.json"
    markdown_path = reports_dir / f"trajectory-{name}.md"
    atomic_write_text(json_path, json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    atomic_write_text(markdown_path, _render_markdown(record))
    record["outputs"] = {
        "json": str(json_path.relative_to(challenge_dir)),
        "markdown": str(markdown_path.relative_to(challenge_dir)),
    }
    return record


def _render_markdown(record: dict[str, Any]) -> str:
    challenge = record["challenge"]
    lines = [
        "# Trajectory",
        "",
        f"- Challenge: `{challenge['name']}` ({challenge['category']})",
        f"- Event: `{challenge['event']}` ｜ Mode: `{challenge['mode']}`",
        f"- Status: `{record['status']}` ｜ Verdict: `{record['verdict']}`",
        f"- Final flag: `{record['final_flag']}`" if record["final_flag"] else "- Final flag: (none)",
        f"- Generated: `{record['generated_at']}`",
        "",
        f"Summary: {record['summary']}",
        "",
    ]
    for item in record["trajectory"]:
        if item["kind"] == "action":
            lines.append(f"- `{item['log']}` `{item['command']}` (rc={item['exit_code']}, {item['duration_ms']}ms)")
        elif item["kind"] == "agent_round":
            lines.append(f"- round {item['round']}: {item['thought']}")
            for action in item.get("actions", []):
                lines.append(f"    - {action.get('argv')} rc={action.get('rc')}")
        elif item["kind"] == "evidence":
            lines.append(f"- {item['id']} ({item['source']}): {item['observation']}")
    return "\n".join(lines) + "\n"
