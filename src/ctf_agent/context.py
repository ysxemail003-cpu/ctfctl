from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .scope import ScopeStore
from .state import StateStore


def _log_sort_key(path: Path) -> tuple[int, str]:
    match = re.match(r"^(\d{6})-", path.name)
    return (int(match.group(1)) if match else 999999, path.name)


def _load_logs(challenge_dir: Path, limit: int) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = []
    log_dir = challenge_dir / "logs"
    if not log_dir.is_dir():
        return logs
    from .logindex import INDEX_FILENAME

    for path in sorted(log_dir.glob("*.json"), key=_log_sort_key, reverse=True)[:limit]:
        if path.name == INDEX_FILENAME:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        logs.append(
            {
                "id": data.get("id", path.stem),
                "tag": data.get("tag"),
                "class": data.get("class"),
                "command": data.get("command_display") or data.get("command"),
                "exit_code": data.get("exit_code"),
                "stdout_file": data.get("stdout_file"),
                "stderr_file": data.get("stderr_file"),
                "scope_check": data.get("scope_check"),
            }
        )
    return list(reversed(logs))


def _file_inventory(directory: Path, limit: int = 30) -> list[str]:
    if not directory.is_dir():
        return []
    files = [str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()]
    return sorted(files)[:limit]


def build_context(challenge_dir: Path, max_logs: int = 12, max_evidence: int = 12) -> dict[str, Any]:
    challenge_dir = challenge_dir.expanduser().resolve()
    state = StateStore(challenge_dir).load()
    scope = ScopeStore(challenge_dir).load()
    evidence = EvidenceLedger(challenge_dir).records()
    challenge = state.get("challenge", {})
    facts = state.get("facts", [])
    hypotheses = state.get("hypotheses", [])
    open_hypotheses = [item for item in hypotheses if item.get("status") == "OPEN"]
    techniques = state.get("techniques", {})
    flag = state.get("flag", {})

    auth = scope.get("authorization", {})
    rules = auth.get("rules", {})
    targets = [
        {
            "host": item.get("host"),
            "ports": item.get("ports", []),
            "description": item.get("description"),
        }
        for item in scope.get("targets", [])
    ]
    category = str(challenge.get("category", "MISC")).lower()
    specialist = {
        "web": "ctf-agent-web",
        "pwn": "ctf-agent-pwn",
        "rev": "ctf-agent-rev",
        "reverse": "ctf-agent-rev",
    }.get(category)

    decisions: list[str] = []
    if not auth.get("confirmed"):
        decisions.append("Confirm event authorization and AI mode")
    if flag.get("status") in {"CANDIDATE", "REPRODUCED"} and not flag.get("submission", {}).get("accepted"):
        decisions.append("Decide whether to submit the flag")
    if state.get("status") == "BLOCKED":
        decisions.append("Choose a new direction or provide missing information")

    return {
        "schema_version": 1,
        "challenge_dir": str(challenge_dir),
        "challenge": challenge,
        "status": state.get("status"),
        "authorization": {
            "mode": auth.get("mode") or challenge.get("mode"),
            "confirmed": auth.get("confirmed", False),
            "rules": rules,
        },
        "scope": {
            "targets": targets,
            "last_check": scope.get("last_check"),
            "limits": scope.get("limits", {}),
        },
        "operator_constraints": state.get("operator_constraints", []),
        "objective": state.get("current_objective"),
        "next_action": state.get("next_action"),
        "facts": facts,
        "hypotheses": hypotheses,
        "open_hypotheses": open_hypotheses,
        "successful_techniques": techniques.get("successful", []),
        "failed_techniques": techniques.get("failed", []),
        "flag": {
            "status": flag.get("status"),
            "value": flag.get("value") if flag.get("status") in {"CANDIDATE", "REPRODUCED", "ACCEPTED"} else None,
            "reproduction": flag.get("reproduction", {}),
            "submission": flag.get("submission", {}),
        },
        "recent_evidence": evidence[-max_evidence:],
        "recent_logs": _load_logs(challenge_dir, max_logs),
        "original_files": _file_inventory(challenge_dir / "original"),
        "work_files": _file_inventory(challenge_dir / "work"),
        "reports": _file_inventory(challenge_dir / "reports"),
        "specialist": specialist,
        "decisions": decisions,
        "context_hint": (
            "Resume from next_action. Use the category specialist if depth is needed. "
            "Ask only for listed decisions or new high-risk actions."
        ),
    }


def render_context_markdown(data: dict[str, Any]) -> str:
    challenge = data.get("challenge", {})
    auth = data.get("authorization", {})
    lines = [
        "# CTF Context",
        "",
        f"- Challenge: `{challenge.get('name')}`",
        f"- Event: `{challenge.get('event')}`",
        f"- Category: `{challenge.get('category')}`",
        f"- Status: `{data.get('status')}`",
        f"- AI mode: `{auth.get('mode')}`",
        f"- Authorization confirmed: `{auth.get('confirmed')}`",
        f"- Objective: {data.get('objective')}",
        f"- Operator constraints: {', '.join(data.get('operator_constraints', [])) or 'NONE'}",
        f"- Next action: {data.get('next_action')}",
        "",
        "## Authorized Targets",
        "",
    ]
    targets = data.get("scope", {}).get("targets", [])
    if targets:
        for target in targets:
            ports = ", ".join(map(str, target.get("ports", []))) or "any"
            lines.append(f"- `{target.get('host')}` — ports: {ports}")
    else:
        lines.append("- None recorded.")

    lines.extend(["", "## Facts", ""])
    facts = data.get("facts", [])
    if not facts:
        lines.append("- None recorded.")
    for fact in facts:
        evidence = ", ".join(fact.get("evidence", [])) or "NONE"
        lines.append(
            f"- `{fact.get('id')}` [{fact.get('classification')}/{fact.get('confidence')}] "
            f"{fact.get('statement')} — evidence: {evidence}"
        )

    lines.extend(["", "## Hypotheses", ""])
    hypotheses = data.get("hypotheses", [])
    if not hypotheses:
        lines.append("- None recorded.")
    for hyp in hypotheses:
        lines.extend(
            [
                f"### {hyp.get('id')} — {hyp.get('status')}",
                "",
                f"- Statement: {hyp.get('statement')}",
                f"- Confidence: `{hyp.get('confidence')}`",
                f"- Test: {hyp.get('test')}",
                f"- Expected: {hyp.get('expected')}",
                f"- Result: {hyp.get('result') or 'NOT RUN'}",
                "",
            ]
        )

    lines.extend(["## Failed Techniques", ""])
    failed = data.get("failed_techniques", [])
    if not failed:
        lines.append("- None recorded.")
    for item in failed:
        lines.append(f"- {item.get('technique')} — evidence: {', '.join(item.get('evidence', [])) or 'NONE'}")

    lines.extend(["", "## Recent Commands", ""])
    logs = data.get("recent_logs", [])
    if not logs:
        lines.append("- None recorded.")
    for log in logs:
        lines.append(
            f"- `{log.get('id')}` `{log.get('tag')}` exit={log.get('exit_code')} — `{log.get('command')}`"
        )

    flag = data.get("flag", {})
    lines.extend(
        [
            "",
            "## Flag",
            "",
            f"- Status: `{flag.get('status')}`",
            f"- Reproduced: `{flag.get('reproduction', {}).get('verified')}`",
            f"- Accepted: `{flag.get('submission', {}).get('accepted')}`",
            "",
            "## Decisions Needed",
            "",
        ]
    )
    decisions = data.get("decisions", [])
    if decisions:
        lines.extend(f"- {item}" for item in decisions)
    else:
        lines.append("- None; continue with the next action.")
    lines.extend(
        [
            "",
            "## Resume Instruction",
            "",
            str(data.get("context_hint")),
            "",
        ]
    )
    return "\n".join(lines)
