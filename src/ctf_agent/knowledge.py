"""Cross-challenge knowledge ledger and post-solve review (Phase G).

Stores what worked and what did not — by category, technique and trigger —
so the solve loop can stop repeating failures. Two hard rules:

1. **No answers.** Entries never contain flags, plaintexts, or full solutions;
   ``flag{...}``-like content is rejected and the whole ledger is scan-guarded.
2. **Evidence-backed.** Every entry must reference resolvable ``LOG-*``/``E-*``
   records from the challenge it was learned in (provenance stays traceable).

Storage: ``<workspace>/knowledge.jsonl`` (shared across all challenges in a
workspace). Review files land in ``<challenge>/reports/review-<name>.md``.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import CTFError
from .evidence import validate_evidence_refs
from .state import StateStore
from .util import append_jsonl, next_id, utcnow

FLAG_LIKE = re.compile(r"flag\{", re.IGNORECASE)
ENTRY_ID_RE = re.compile(r"^K-\d{6}$")
MAX_LEN = {"category": 32, "technique": 300, "trigger": 300, "conclusion": 500}


def workspace_root(challenge_dir: Path) -> Path:
    """Workspace root for a challenge dir (``<ws>/contests/<event>/<name>``)."""
    challenge_dir = challenge_dir.resolve()
    if not (challenge_dir / "state.yaml").is_file():
        raise CTFError(f"Not a challenge directory (missing state.yaml): {challenge_dir}")
    return challenge_dir.parents[2]


def _ledger_path(workspace: Path) -> Path:
    return workspace.resolve() / "knowledge.jsonl"


def _guard_text(field: str, value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise CTFError(f"{field} is required.")
    if len(text) > MAX_LEN.get(field, 300):
        raise CTFError(f"{field} too long (max {MAX_LEN.get(field, 300)} chars).")
    if FLAG_LIKE.search(text):
        raise CTFError(
            f"{field} looks like it contains a flag/answer; knowledge stores techniques, not answers."
        )
    return text


def add_entry(
    challenge_dir: Path,
    *,
    category: str,
    technique: str,
    trigger: str,
    conclusion: str,
    outcome: str,
    evidence_refs: list[str],
) -> dict[str, Any]:
    """Add one evidence-backed knowledge entry to the workspace ledger."""
    challenge_dir = challenge_dir.resolve()
    outcome = (outcome or "").strip().lower()
    if outcome not in {"successful", "failed"}:
        raise CTFError("outcome must be 'successful' or 'failed'.")
    refs = [str(ref).strip() for ref in evidence_refs if str(ref).strip()]
    if not refs:
        raise CTFError("knowledge entries require at least one evidence reference (LOG-*/E-*).")
    validate_evidence_refs(challenge_dir, refs)  # raises on unresolved evidence

    category_text = _guard_text("category", category).upper()
    technique_text = _guard_text("technique", technique)
    trigger_text = _guard_text("trigger", trigger)
    conclusion_text = _guard_text("conclusion", conclusion)

    workspace = workspace_root(challenge_dir)
    ledger = _ledger_path(workspace)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "id": next_id(ledger, "K"),
        "category": category_text,
        "technique": technique_text,
        "trigger": trigger_text,
        "conclusion": conclusion_text,
        "outcome": outcome,
        "evidence_refs": refs,
        "source_challenge": str((StateStore(challenge_dir).load().get("challenge") or {}).get("name", challenge_dir.name)),
        "created_at": utcnow(),
    }
    append_jsonl(ledger, entry)
    return entry


def list_entries(
    workspace: Path,
    category: str | None = None,
    outcome: str | None = None,
) -> list[dict[str, Any]]:
    """List knowledge entries, optionally filtered by category/outcome."""
    ledger = _ledger_path(workspace)
    if not ledger.is_file():
        return []
    entries: list[dict[str, Any]] = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if category and str(item.get("category", "")).upper() != str(category).upper():
            continue
        if outcome and str(item.get("outcome", "")).lower() != str(outcome).lower():
            continue
        entries.append(item)
    return entries


def match_entries(challenge_dir: Path, category: str, limit: int = 3) -> list[dict[str, Any]]:
    """Entries to inject into a solve round: same category, successful first."""
    workspace = workspace_root(challenge_dir)
    entries = list_entries(workspace, category=category)
    entries.sort(key=lambda item: (0 if str(item.get("outcome", "")) == "successful" else 1, str(item.get("created_at", ""))), reverse=False)
    return entries[: max(1, int(limit))]


def propose_from_workspace(workspace: Path) -> list[dict[str, Any]]:
    """Scan every challenge's recorded techniques and propose ledger entries.

    Proposals only include techniques that carry evidence references; the
    operator commits them with the knowledge CLI (nothing is auto-written).
    """
    workspace = workspace.resolve()
    contests = workspace / "contests"
    proposals: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    if not contests.is_dir():
        return proposals
    for state_path in sorted(contests.glob("*/*/state.yaml")):
        challenge_dir = state_path.parent
        try:
            data = StateStore(challenge_dir).load()
        except Exception:
            continue
        meta = data.get("challenge") or {}
        category = str(meta.get("category", "MISC")).upper()
        name = str(meta.get("name", challenge_dir.name))
        techniques = data.get("techniques") or {}
        for outcome in ("successful", "failed"):
            for item in techniques.get(outcome, []) or []:
                if not isinstance(item, dict):
                    continue
                technique = str(item.get("technique", "")).strip()
                refs = [str(ref) for ref in item.get("evidence") or [] if str(ref).strip()]
                if not technique or not refs or FLAG_LIKE.search(technique):
                    continue
                key = (category, outcome, technique)
                if key in seen:
                    continue
                seen.add(key)
                proposals.append(
                    {
                        "category": category,
                        "technique": technique,
                        "trigger": f"similar {category} challenge",
                        "conclusion": f"learned while solving {name} ({outcome})",
                        "outcome": outcome,
                        "evidence_refs": refs,
                        "source_challenge": name,
                    }
                )
    return proposals


def stats(workspace: Path) -> dict[str, Any]:
    """Entry counts and the repeat-failure signal (failed techniques re-learned)."""
    entries = list_entries(workspace)
    by_outcome: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for entry in entries:
        outcome = str(entry.get("outcome", "failed"))
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        category = str(entry.get("category", "MISC"))
        by_category[category] = by_category.get(category, 0) + 1
    return {
        "total": len(entries),
        "by_outcome": by_outcome,
        "by_category": by_category,
        "scan": "ok" if not any(FLAG_LIKE.search(json.dumps(e, ensure_ascii=False)) for e in entries) else "flag-like content detected!",
    }


def generate_review(challenge_dir: Path) -> dict[str, Any]:
    """Write a post-solve review markdown for one challenge."""
    challenge_dir = challenge_dir.resolve()
    if not (challenge_dir / "state.yaml").is_file():
        raise CTFError(f"Not a challenge directory (missing state.yaml): {challenge_dir}")
    state = StateStore(challenge_dir).load()
    meta = state.get("challenge") or {}
    name = str(meta.get("name", challenge_dir.name))
    flag = state.get("flag") or {}

    events: list[str] = []
    events_path = challenge_dir / "events.jsonl"
    if events_path.is_file():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(f"- `{item.get('id')}` {item.get('type')} @ {item.get('timestamp')}")
    events = events[-60:]

    rounds_dir = challenge_dir / "agent_rounds"
    round_dirs = sorted(p.name for p in rounds_dir.glob("round-*")) if rounds_dir.is_dir() else []

    techniques = state.get("techniques") or {}
    successful = [str(i.get("technique")) for i in techniques.get("successful", []) if isinstance(i, dict)]
    failed = [str(i.get("technique")) for i in techniques.get("failed", []) if isinstance(i, dict)]

    lines = [
        "# Review",
        "",
        f"- Challenge: `{name}` ({meta.get('category')})",
        f"- Status: `{state.get('status')}` ｜ Flag: `{flag.get('status')}`",
        f"- Facts: {len(state.get('facts') or [])} ｜ Hypotheses: {len(state.get('hypotheses') or [])}",
        f"- Agent rounds: {len(round_dirs)} ｜ Events: {len(events)}",
        "",
        "## Timeline (recent events)",
        "",
        *events,
        "",
        "## Techniques",
        "",
        "### Successful",
    ]
    lines.extend(f"- {item}" for item in successful)
    if not successful:
        lines.append("- (none)")
    lines += ["", "### Failed (waste points)"]
    lines.extend(f"- {item}" for item in failed)
    if not failed:
        lines.append("- (none)")
    lines += [
        "",
        "## Reusable knowledge",
        "",
        "Record anything reusable with `ctfctl knowledge add --outcome successful|failed ...`.",
        "",
    ]
    reports_dir = challenge_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    output = reports_dir / f"review-{name}.md"
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "challenge": name,
        "output": str(output.relative_to(challenge_dir)),
        "successful": successful,
        "failed": failed,
    }
