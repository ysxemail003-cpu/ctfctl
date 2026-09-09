from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import CTFError
from .evidence import EvidenceLedger, validate_evidence_refs
from .runtime_lock import challenge_lock
from .state import StateStore
from .util import append_jsonl, atomic_write_text, sha256_file, utcnow

RESULT_SCHEMA_VERSION = 2
SUPPORTED_RESULT_SCHEMAS = {1, 2}
MERGE_HISTORY_FILE = "reports/merged-results.jsonl"
VALID_RESULT_STATUSES = {"COMPLETE", "PARTIAL", "FAILED", "BLOCKED"}
VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
VALID_FACT_CLASSIFICATIONS = {"FACT", "INFERENCE", "UNKNOWN"}


def _yaml_block(data: Any) -> str:
    import yaml

    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True).strip()


def final_report(
    challenge_dir: Path,
    root_cause: str,
    attack_path: list[str],
    exploit: str,
    verification: str,
    lessons: list[str],
    output: Path | None = None,
) -> Path:
    state = StateStore(challenge_dir).load()
    evidence = EvidenceLedger(challenge_dir).records()
    challenge = state.get("challenge", {})
    flag = state.get("flag", {})
    accepted = flag.get("submission", {}).get("accepted", False)
    value = flag.get("value") if accepted else None
    output = output or challenge_dir / "reports" / "final.md"
    content = f"""# Final Solve Report — {challenge.get('name')}

Generated: `{utcnow()}`

## Challenge

- Event: `{challenge.get('event')}`
- Name: `{challenge.get('name')}`
- Category: `{challenge.get('category')}`
- AI mode: `{challenge.get('mode')}`
- Final status: `{state.get('status')}`

## Root Cause

{root_cause}

## Attack Path

"""
    for index, step in enumerate(attack_path, 1):
        content += f"{index}. {step}\n"
    content += f"""
## Exploit

```text
{exploit}
```

## Verification

{verification}

## Flag

- Status: `{flag.get('status')}`
- Reproduced: `{flag.get('reproduction', {}).get('verified')}`
- Platform accepted: `{accepted}`
- Value: `{value if accepted else 'REDACTED_UNTIL_ACCEPTED'}`

## State Snapshot

```yaml
{_yaml_block(state)}
```

## Evidence

"""
    if not evidence:
        content += "No evidence records.\n"
    for item in evidence:
        content += f"- `{item['id']}` {item['observation']} — source `{item['source']}`\n"
    content += "\n## Lessons\n\n"
    for lesson in lessons:
        content += f"- {lesson}\n"
    content += "\n"
    atomic_write_text(output, content)
    return output


def handoff(
    challenge_dir: Path,
    agent: str,
    objective: str,
    inputs: list[str],
    constraints: list[str],
    expected_output: str = "reports/result-<agent>.json using templates/agent-result.json",
) -> Path:
    state = StateStore(challenge_dir).load()
    evidence = EvidenceLedger(challenge_dir).records()
    safe_agent = "".join(char if char.isalnum() or char in "-_" else "-" for char in agent).strip("-").lower()
    output = challenge_dir / "reports" / f"handoff-{safe_agent}.md"
    content = f"""# Handoff — {agent}

Generated: `{utcnow()}`

## Objective

{objective}

## Inputs

"""
    for item in inputs:
        content += f"- `{item}`\n"
    content += "\n## Constraints\n\n"
    for item in constraints:
        content += f"- {item}\n"
    content += f"""
## Expected Output

`{expected_output}`

## State Snapshot

```yaml
{_yaml_block(state)}
```

## Evidence Snapshot

```yaml
{_yaml_block(evidence)}
```

## Specialist Rules

1. Do not modify canonical `state.yaml`.
2. Do not attack outside `.scope.yaml`.
3. Use `ctfctl run` or `ctfctl tool` for all substantive commands.
4. Return facts, hypotheses, failed techniques, artifacts, and a recommended next action.
"""
    atomic_write_text(output, content)
    return output


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise CTFError(message)


def _default_ref(result_path: Path, challenge_dir: Path) -> str:
    return str(result_path.relative_to(challenge_dir))


def _validate_evidence_list(
    challenge_dir: Path,
    evidence: Any,
    result_path: Path,
    *,
    default: bool,
) -> list[str]:
    refs: list[str]
    if evidence is None and default:
        refs = [_default_ref(result_path, challenge_dir)]
    elif evidence is None:
        refs = []
    else:
        _require(isinstance(evidence, list), "evidence must be a list of references")
        _require(all(isinstance(ref, str) for ref in evidence), "evidence references must be strings")
        refs = [ref for ref in evidence if str(ref).strip()]
    # Reject unresolved references before any state mutation (atomic merge).
    validate_evidence_refs(challenge_dir, refs)
    return refs


def _normalize_result(
    challenge_dir: Path,
    result_path: Path,
    raw: Any,
) -> tuple[dict[str, Any], str]:
    """Validate a specialist result and normalize it to schema v2 semantics.

    Returns ``(normalized, source_hash)``. ``source_hash`` is the SHA-256 of the
    result file content; when the file declares one it must match. Old results
    without ``result_id``/``source_hash`` stay compatible and derive both from
    the file content.
    """
    _require(isinstance(raw, dict), "Agent result must be a JSON object")
    schema = raw.get("schema_version", 1)
    _require(
        isinstance(schema, int) and schema in SUPPORTED_RESULT_SCHEMAS,
        f"Unsupported agent result schema_version: {schema!r}",
    )
    required = {"agent", "status", "facts", "hypotheses", "recommended_next_action"}
    missing = required - raw.keys()
    _require(not missing, f"Agent result missing fields: {', '.join(sorted(missing))}")
    _require(isinstance(raw["agent"], str) and raw["agent"].strip(), "agent must be a non-empty string")
    status = str(raw["status"]).upper()
    _require(status in VALID_RESULT_STATUSES, f"Invalid result status: {raw['status']!r}")
    _require(isinstance(raw["facts"], list), "facts must be a list")
    _require(isinstance(raw["hypotheses"], list), "hypotheses must be a list")
    _require(
        isinstance(raw["recommended_next_action"], str),
        "recommended_next_action must be a string",
    )
    failed = raw.get("failed_techniques", [])
    _require(isinstance(failed, list), "failed_techniques must be a list")

    actual_hash = sha256_file(result_path)
    declared_hash = raw.get("source_hash")
    if declared_hash:
        _require(
            declared_hash == actual_hash,
            "source_hash does not match the result file content",
        )
    source_hash = actual_hash
    result_id = raw.get("result_id")
    if not isinstance(result_id, str) or not result_id.strip():
        result_id = f"RES-{source_hash[:16].upper()}"

    facts: list[dict[str, Any]] = []
    for fact in raw["facts"]:
        _require(isinstance(fact, dict), "each fact must be an object")
        _require(
            isinstance(fact.get("statement"), str) and fact["statement"].strip(),
            "each fact must have a non-empty statement",
        )
        confidence = str(fact.get("confidence", "MEDIUM")).upper()
        _require(confidence in VALID_CONFIDENCE, f"Invalid fact confidence: {fact.get('confidence')!r}")
        classification = str(fact.get("classification", "FACT")).upper()
        _require(
            classification in VALID_FACT_CLASSIFICATIONS,
            f"Invalid fact classification: {fact.get('classification')!r}",
        )
        evidence = _validate_evidence_list(
            challenge_dir,
            fact.get("evidence"),
            result_path,
            default="evidence" not in fact,
        )
        facts.append(
            {
                "statement": fact["statement"],
                "evidence": evidence,
                "confidence": confidence,
                "classification": classification,
            }
        )

    hypotheses: list[dict[str, Any]] = []
    for hypothesis in raw["hypotheses"]:
        _require(isinstance(hypothesis, dict), "each hypothesis must be an object")
        for field in ("statement", "test", "expected"):
            _require(
                isinstance(hypothesis.get(field), str) and hypothesis[field].strip(),
                f"each hypothesis must have a non-empty {field}",
            )
        confidence = str(hypothesis.get("confidence", "MEDIUM")).upper()
        _require(confidence in VALID_CONFIDENCE, f"Invalid hypothesis confidence: {hypothesis.get('confidence')!r}")
        evidence = _validate_evidence_list(
            challenge_dir,
            hypothesis.get("evidence"),
            result_path,
            default="evidence" not in hypothesis,
        )
        hypotheses.append(
            {
                "statement": hypothesis["statement"],
                "test": hypothesis["test"],
                "expected": hypothesis["expected"],
                "confidence": confidence,
                "evidence": evidence,
            }
        )

    techniques: list[dict[str, Any]] = []
    for technique in failed:
        if isinstance(technique, str):
            techniques.append(
                {
                    "technique": technique,
                    "evidence": [_default_ref(result_path, challenge_dir)],
                    "classification": None,
                }
            )
            continue
        _require(isinstance(technique, dict), "failed_techniques entries must be strings or objects")
        _require(
            isinstance(technique.get("technique"), str) and technique["technique"].strip(),
            "each failed technique object needs a non-empty technique",
        )
        evidence = _validate_evidence_list(
            challenge_dir,
            technique.get("evidence"),
            result_path,
            default="evidence" not in technique,
        )
        classification = technique.get("classification")
        if classification is not None:
            _require(isinstance(classification, str), "technique classification must be a string")
        techniques.append(
            {
                "technique": technique["technique"],
                "evidence": evidence,
                "classification": classification,
            }
        )

    normalized = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "result_id": result_id,
        "agent": raw["agent"],
        "status": status,
        "objective": raw.get("objective"),
        "facts": facts,
        "hypotheses": hypotheses,
        "failed_techniques": techniques,
        "recommended_next_action": raw["recommended_next_action"],
        "source_hash": source_hash,
        "risk": raw.get("risk"),
        "confidence": raw.get("confidence"),
    }
    return normalized, source_hash


def _merge_history(challenge_dir: Path) -> list[dict[str, Any]]:
    path = challenge_dir / MERGE_HISTORY_FILE
    if not path.is_file():
        return []
    history: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            history.append(record)
    return history


def _fact_key(fact: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return (fact["statement"], tuple(sorted(fact.get("evidence", []))))


def _hypothesis_key(hypothesis: dict[str, Any]) -> tuple[str, str, str, tuple[str, ...]]:
    return (
        hypothesis["statement"],
        hypothesis["test"],
        hypothesis["expected"],
        tuple(sorted(hypothesis.get("evidence", []))),
    )


def _technique_key(technique: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return (technique["technique"], tuple(sorted(technique.get("evidence", []))))


def merge_result(challenge_dir: Path, result_path: Path) -> dict[str, Any]:
    """Merge a specialist result into canonical state (idempotent).

    Validation (schema, evidence references, types) happens before any state
    mutation so a rejected result never leaves partial state. Merging the same
    file twice records a single entry in ``reports/merged-results.jsonl`` and
    returns ``{"merged": False, "reason": "already_merged", ...}``.
    """
    challenge_dir = challenge_dir.resolve()
    if not result_path.is_file():
        raise CTFError(f"Result file not found: {result_path}")
    try:
        raw = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CTFError(f"Invalid JSON result: {exc}") from exc
    normalized, source_hash = _normalize_result(challenge_dir, result_path, raw)

    with challenge_lock(challenge_dir, description="merge_result"):
        history = _merge_history(challenge_dir)
        for entry in history:
            if entry.get("source_hash") == source_hash:
                return {
                    "merged": False,
                    "reason": "already_merged",
                    "result_id": entry.get("result_id") or normalized["result_id"],
                    "agent": entry.get("agent") or normalized["agent"],
                    "status": entry.get("status") or normalized["status"],
                    "source_hash": source_hash,
                }

        state_store = StateStore(challenge_dir)
        current = state_store.load()
        added: dict[str, Any] = {"facts": [], "hypotheses": [], "techniques": []}

        known_facts = {_fact_key(fact) for fact in current.get("facts", []) if isinstance(fact, dict) and fact.get("statement")}
        known_hypotheses = {
            _hypothesis_key(hyp)
            for hyp in current.get("hypotheses", [])
            if isinstance(hyp, dict) and hyp.get("statement")
        }
        known_techniques = {
            _technique_key(item)
            for outcome in current.get("techniques", {}).values()
            for item in outcome
            if isinstance(item, dict) and item.get("technique")
        }

        for fact in normalized["facts"]:
            if _fact_key(fact) in known_facts:
                continue
            record = state_store.add_fact(
                statement=fact["statement"],
                evidence=fact["evidence"],
                confidence=fact["confidence"],
                classification=fact["classification"],
            )
            known_facts.add(_fact_key(fact))
            added["facts"].append(record["id"])

        for hypothesis in normalized["hypotheses"]:
            if _hypothesis_key(hypothesis) in known_hypotheses:
                continue
            record = state_store.add_hypothesis(
                statement=hypothesis["statement"],
                test=hypothesis["test"],
                expected=hypothesis["expected"],
                confidence=hypothesis["confidence"],
                evidence=hypothesis["evidence"],
            )
            known_hypotheses.add(_hypothesis_key(hypothesis))
            added["hypotheses"].append(record["id"])

        for technique in normalized["failed_techniques"]:
            if _technique_key(technique) in known_techniques:
                continue
            record = state_store.add_technique(
                technique["technique"],
                "failed",
                technique["evidence"],
                technique["classification"],
            )
            known_techniques.add(_technique_key(technique))
            added["techniques"].append(record)

        if normalized["recommended_next_action"]:
            state_store.set_next(normalized["recommended_next_action"])
        state_store.event(
            "agent_result_merged",
            {
                "result_id": normalized["result_id"],
                "agent": normalized["agent"],
                "status": normalized["status"],
                "result_file": str(result_path.relative_to(challenge_dir)),
                "source_hash": source_hash,
                "added": added,
            },
        )
        append_jsonl(
            challenge_dir / MERGE_HISTORY_FILE,
            {
                "source_hash": source_hash,
                "result_id": normalized["result_id"],
                "agent": normalized["agent"],
                "status": normalized["status"],
                "result_file": str(result_path.relative_to(challenge_dir)),
                "merged_at": utcnow(),
            },
        )

    return {
        "merged": True,
        "agent": normalized["agent"],
        "status": normalized["status"],
        "result_id": normalized["result_id"],
        "source_hash": source_hash,
        "added": added,
    }
