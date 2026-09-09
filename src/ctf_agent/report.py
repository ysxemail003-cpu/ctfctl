from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import CTFError
from .evidence import EvidenceLedger
from .state import StateStore
from .util import atomic_write_text, utcnow


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


def merge_result(challenge_dir: Path, result_path: Path) -> dict[str, Any]:
    if not result_path.is_file():
        raise CTFError(f"Result file not found: {result_path}")
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CTFError(f"Invalid JSON result: {exc}") from exc
    if not isinstance(result, dict):
        raise CTFError("Agent result must be a JSON object")
    required = {"agent", "status", "facts", "hypotheses", "recommended_next_action"}
    missing = required - result.keys()
    if missing:
        raise CTFError(f"Agent result missing fields: {', '.join(sorted(missing))}")

    state_store = StateStore(challenge_dir)
    added: dict[str, Any] = {"facts": [], "hypotheses": [], "techniques": []}
    for fact in result.get("facts", []):
        if not isinstance(fact, dict) or not fact.get("statement"):
            raise CTFError("Each fact must be an object with a statement")
        record = state_store.add_fact(
            statement=fact["statement"],
            evidence=fact.get("evidence", [str(result_path.relative_to(challenge_dir))]),
            confidence=fact.get("confidence", "MEDIUM"),
            classification=fact.get("classification", "FACT"),
        )
        added["facts"].append(record["id"])
    for hypothesis in result.get("hypotheses", []):
        if not isinstance(hypothesis, dict) or not hypothesis.get("statement"):
            raise CTFError("Each hypothesis must be an object with a statement")
        record = state_store.add_hypothesis(
            statement=hypothesis["statement"],
            test=hypothesis.get("test", "Not supplied"),
            expected=hypothesis.get("expected", "Not supplied"),
            confidence=hypothesis.get("confidence", "MEDIUM"),
            evidence=hypothesis.get("evidence", [str(result_path.relative_to(challenge_dir))]),
        )
        added["hypotheses"].append(record["id"])
    for technique in result.get("failed_techniques", []):
        if isinstance(technique, str):
            record = state_store.add_technique(technique, "failed", [str(result_path.relative_to(challenge_dir))])
        elif isinstance(technique, dict) and technique.get("technique"):
            record = state_store.add_technique(
                technique["technique"],
                "failed",
                technique.get("evidence", [str(result_path.relative_to(challenge_dir))]),
                technique.get("classification"),
            )
        else:
            raise CTFError("failed_techniques entries must be strings or objects with technique")
        added["techniques"].append(record)
    if result.get("recommended_next_action"):
        state_store.set_next(result["recommended_next_action"])
    state_store.event(
        "agent_result_merged",
        {
            "agent": result.get("agent"),
            "status": result.get("status"),
            "result_file": str(result_path.relative_to(challenge_dir)),
            "added": added,
        },
    )
    return {"agent": result.get("agent"), "status": result.get("status"), "added": added}
