from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import StateError
from .util import (
    append_jsonl,
    atomic_write_text,
    atomic_write_yaml,
    next_id,
    read_yaml,
    utcnow,
)

VALID_STATUSES = {
    "INIT",
    "AUTHORIZED",
    "RECON",
    "HYPOTHESIS",
    "TESTING",
    "EXPLOITATION",
    "VERIFICATION",
    "SOLVED",
    "BLOCKED",
    "ABANDONED",
}

VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
VALID_HYPOTHESIS_STATUS = {"OPEN", "CONFIRMED", "REJECTED", "INCONCLUSIVE"}


def default_state(event: str, challenge: str, category: str, mode: str) -> dict[str, Any]:
    now = utcnow()
    return {
        "schema_version": 1,
        "challenge": {
            "event": event,
            "name": challenge,
            "category": category.upper(),
            "mode": mode.upper(),
        },
        "authorization": {
            "confirmed": False,
            "evidence": None,
            "notes": None,
        },
        "status": "INIT",
        "scope": {
            "file": ".scope.yaml",
            "checked_at": None,
        },
        "operator_constraints": [],
        "current_objective": "Establish facts and authorized target scope.",
        "next_action": "Run ctfctl doctor and inspect challenge inputs.",
        "facts": [],
        "hypotheses": [],
        "techniques": {"successful": [], "failed": []},
        "flag": {
            "status": "NONE",
            "value": None,
            "pattern": None,
            "source": [],
            "reproduction": {
                "verified": False,
                "runs": 0,
                "values_match": False,
                "last_log": None,
            },
            "submission": {
                "submitted": False,
                "accepted": False,
                "platform": None,
                "accepted_at": None,
            },
        },
        "created_at": now,
        "updated_at": now,
    }


class StateStore:
    def __init__(self, challenge_dir: Path):
        self.challenge_dir = challenge_dir.resolve()
        self.state_path = self.challenge_dir / "state.yaml"
        self.events_path = self.challenge_dir / "events.jsonl"
        self.evidence_path = self.challenge_dir / "evidence.jsonl"
        if not self.state_path.is_file():
            raise StateError(
                f"No state.yaml in {self.challenge_dir}. Run `ctfctl init` first or use --challenge-dir."
            )

    def load(self) -> dict[str, Any]:
        data = read_yaml(self.state_path)
        if data.get("schema_version") != 1:
            raise StateError(f"Unsupported state schema in {self.state_path}")
        return data

    def save(self, data: dict[str, Any]) -> None:
        data["updated_at"] = utcnow()
        atomic_write_yaml(self.state_path, data)
        self.render(data)

    def event(self, event_type: str, payload: dict[str, Any]) -> str:
        event_id = next_id(self.events_path, "EVT")
        append_jsonl(
            self.events_path,
            {
                "id": event_id,
                "type": event_type,
                "timestamp": utcnow(),
                "payload": payload,
            },
        )
        return event_id

    def transition(self, status: str, reason: str, evidence: list[str] | None = None) -> dict[str, Any]:
        status = status.upper()
        if status not in VALID_STATUSES:
            raise StateError(f"Invalid status {status}; choose one of {', '.join(sorted(VALID_STATUSES))}")
        data = self.load()
        old = data.get("status")
        data["status"] = status
        self.event(
            "state_transition",
            {"from": old, "to": status, "reason": reason, "evidence": evidence or []},
        )
        self.save(data)
        return data

    def add_fact(
        self,
        statement: str,
        evidence: list[str] | None = None,
        confidence: str = "HIGH",
        classification: str = "FACT",
    ) -> dict[str, Any]:
        confidence = confidence.upper()
        classification = classification.upper()
        if confidence not in VALID_CONFIDENCE:
            raise StateError("Confidence must be LOW, MEDIUM, or HIGH")
        if classification not in {"FACT", "INFERENCE", "UNKNOWN"}:
            raise StateError("Classification must be FACT, INFERENCE, or UNKNOWN")
        data = self.load()
        facts = data.setdefault("facts", [])
        fact_id = f"F-{len(facts) + 1:04d}"
        while any(item.get("id") == fact_id for item in facts):
            suffix = int(fact_id.split("-")[1]) + 1
            fact_id = f"F-{suffix:04d}"
        record = {
            "id": fact_id,
            "statement": statement,
            "classification": classification,
            "confidence": confidence,
            "evidence": evidence or [],
            "created_at": utcnow(),
        }
        facts.append(record)
        self.event("fact_added", record)
        self.save(data)
        return record

    def add_hypothesis(
        self,
        statement: str,
        test: str,
        expected: str,
        confidence: str = "MEDIUM",
        evidence: list[str] | None = None,
    ) -> dict[str, Any]:
        confidence = confidence.upper()
        if confidence not in VALID_CONFIDENCE:
            raise StateError("Confidence must be LOW, MEDIUM, or HIGH")
        data = self.load()
        hypotheses = data.setdefault("hypotheses", [])
        hypothesis_id = f"H-{len(hypotheses) + 1:04d}"
        while any(item.get("id") == hypothesis_id for item in hypotheses):
            suffix = int(hypothesis_id.split("-")[1]) + 1
            hypothesis_id = f"H-{suffix:04d}"
        record = {
            "id": hypothesis_id,
            "statement": statement,
            "confidence": confidence,
            "status": "OPEN",
            "evidence": evidence or [],
            "test": test,
            "expected": expected,
            "result": None,
            "created_at": utcnow(),
            "updated_at": utcnow(),
        }
        hypotheses.append(record)
        self.event("hypothesis_added", record)
        self.save(data)
        return record

    def update_hypothesis(self, hypothesis_id: str, status: str, result: str) -> dict[str, Any]:
        status = status.upper()
        if status not in VALID_HYPOTHESIS_STATUS:
            raise StateError("Hypothesis status must be OPEN, CONFIRMED, REJECTED, or INCONCLUSIVE")
        data = self.load()
        for item in data.get("hypotheses", []):
            if item.get("id", "").upper() == hypothesis_id.upper():
                item["status"] = status
                item["result"] = result
                item["updated_at"] = utcnow()
                self.event("hypothesis_updated", item)
                self.save(data)
                return item
        raise StateError(f"Unknown hypothesis: {hypothesis_id}")

    def set_constraints(self, constraints: list[str]) -> list[str]:
        data = self.load()
        normalized = sorted({str(item).strip() for item in constraints if str(item).strip()})
        data["operator_constraints"] = normalized
        self.event("operator_constraints_updated", {"constraints": normalized})
        self.save(data)
        return normalized

    def remove_constraint(self, constraint: str) -> list[str]:
        data = self.load()
        constraints = [item for item in data.get("operator_constraints", []) if item != constraint]
        data["operator_constraints"] = constraints
        self.event("operator_constraints_updated", {"constraints": constraints, "removed": constraint})
        self.save(data)
        return constraints

    def set_next(self, next_action: str, objective: str | None = None) -> dict[str, Any]:
        data = self.load()
        data["next_action"] = next_action
        if objective is not None:
            data["current_objective"] = objective
        self.event(
            "next_action",
            {"next_action": next_action, "objective": data.get("current_objective")},
        )
        self.save(data)
        return data

    def add_technique(self, technique: str, outcome: str, evidence: list[str] | None = None, classification: str | None = None) -> dict[str, Any]:
        outcome = outcome.lower()
        if outcome not in {"successful", "failed"}:
            raise StateError("Technique outcome must be successful or failed")
        data = self.load()
        record = {
            "technique": technique,
            "evidence": evidence or [],
            "classification": classification,
            "timestamp": utcnow(),
        }
        data.setdefault("techniques", {}).setdefault(outcome, []).append(record)
        self.event("technique_recorded", {"outcome": outcome, **record})
        self.save(data)
        return record

    def update_flag(self, patch: dict[str, Any], event_type: str = "flag_updated") -> dict[str, Any]:
        data = self.load()
        flag = data.setdefault("flag", {})
        current_repro = flag.setdefault("reproduction", {})
        current_sub = flag.setdefault("submission", {})
        for key, value in patch.items():
            if key == "reproduction":
                current_repro.update(value)
            elif key == "submission":
                current_sub.update(value)
            else:
                flag[key] = value
        self.event(event_type, flag)
        self.save(data)
        return flag

    def render(self, data: dict[str, Any] | None = None) -> str:
        data = data or self.load()
        challenge = data.get("challenge", {})
        flag = data.get("flag", {})
        repro = flag.get("reproduction", {})
        submission = flag.get("submission", {})
        lines = [
            f"# STATE — {challenge.get('name', 'challenge')}",
            "",
            "> Generated from `state.yaml`. Do not edit this file manually.",
            "",
            "## Snapshot",
            "",
            f"- Event: `{challenge.get('event')}`",
            f"- Category: `{challenge.get('category')}`",
            f"- AI Mode: `{challenge.get('mode')}`",
            f"- Status: `{data.get('status')}`",
            f"- Authorization confirmed: `{data.get('authorization', {}).get('confirmed')}`",
            f"- Operator constraints: {', '.join(data.get('operator_constraints', [])) or 'NONE'}",
            f"- Current objective: {data.get('current_objective')}",
            f"- Next action: {data.get('next_action')}",
            "",
            "## Facts",
            "",
        ]
        facts = data.get("facts", [])
        if not facts:
            lines.append("- None recorded.")
        for fact in facts:
            lines.extend(
                [
                    f"### {fact.get('id')}",
                    "",
                    str(fact.get("statement")),
                    "",
                    f"- Classification: `{fact.get('classification')}`",
                    f"- Confidence: `{fact.get('confidence')}`",
                    f"- Evidence: {', '.join(fact.get('evidence', [])) or 'NONE'}",
                    "",
                ]
            )
        lines.extend(["## Hypotheses", ""])
        hypotheses = data.get("hypotheses", [])
        if not hypotheses:
            lines.append("- None recorded.")
        for hyp in hypotheses:
            lines.extend(
                [
                    f"### {hyp.get('id')} — {hyp.get('status')}",
                    "",
                    str(hyp.get("statement")),
                    "",
                    f"- Confidence: `{hyp.get('confidence')}`",
                    f"- Test: {hyp.get('test')}",
                    f"- Expected: {hyp.get('expected')}",
                    f"- Result: {hyp.get('result') or 'NOT RUN'}",
                    f"- Evidence: {', '.join(hyp.get('evidence', [])) or 'NONE'}",
                    "",
                ]
            )
        techniques = data.get("techniques", {})
        lines.extend(["", "## Successful Techniques", ""])
        successful = techniques.get("successful", [])
        if successful:
            lines.extend(f"- {item.get('technique')}" for item in successful)
        else:
            lines.append("- None")
        lines.extend(["", "## Failed Techniques", ""])
        failed = techniques.get("failed", [])
        if failed:
            lines.extend(f"- {item.get('technique')}" for item in failed)
        else:
            lines.append("- None")
        lines.extend(
            [
                "",
                "## Flag",
                "",
                f"- Status: `{flag.get('status')}`",
                f"- Reproduced: `{repro.get('verified')}`",
                f"- Reproduction runs: `{repro.get('runs')}`",
                f"- Submitted: `{submission.get('submitted')}`",
                f"- Accepted: `{submission.get('accepted')}`",
                "",
            ]
        )
        content = "\n".join(lines)
        atomic_write_text(self.challenge_dir / "STATE.md", content)
        return content
