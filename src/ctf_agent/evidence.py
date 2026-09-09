"""Evidence ledger and strict evidence-reference resolution.

Every FACT, INFERENCE, HYPOTHESIS, technique result, or state transition must
reference resolvable evidence: a real ``LOG-*`` metadata record with intact
output files, a real ``E-*`` ledger record, or an artifact file inside the
challenge directory that does not escape through symlinks.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .errors import CTFError
from .runtime_lock import challenge_lock
from .util import append_jsonl, atomic_write_text, next_id, utcnow

LOG_ID_RE = re.compile(r"LOG-\d{6}")
EVIDENCE_ID_RE = re.compile(r"E-\d{6}")


def _path_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def resolve_evidence_ref(challenge_dir: Path, ref: str) -> dict[str, str]:
    """Resolve one evidence reference to a concrete, existing artifact.

    Returns a small descriptor (kind/ref/path). Raises :class:`CTFError` when
    the reference cannot be resolved, so unresolved evidence is rejected by
    default.
    """
    challenge_dir = challenge_dir.resolve()
    ref = str(ref).strip()
    if not ref:
        raise CTFError("Empty evidence reference is not allowed")

    log_match = LOG_ID_RE.fullmatch(ref)
    if log_match:
        log_dir = challenge_dir / "logs"
        sequence = log_match.group(0).split("-")[1]
        if log_dir.is_dir():
            for path in sorted(log_dir.glob(f"{sequence}-*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if data.get("id") != ref:
                    continue
                for field in ("stdout_file", "stderr_file", "transcript_file"):
                    relative = data.get(field)
                    if not relative:
                        continue
                    target = (challenge_dir / str(relative)).resolve()
                    if not _path_within(challenge_dir, target) or not target.is_file():
                        raise CTFError(
                            f"Evidence reference {ref} points to a missing or escaping {field}: {relative}"
                        )
                return {"kind": "log", "ref": ref, "path": str(path.relative_to(challenge_dir))}
        raise CTFError(
            f"Unresolved evidence reference {ref}: no matching metadata in logs/"
        )

    if EVIDENCE_ID_RE.fullmatch(ref):
        ledger_path = challenge_dir / "evidence.jsonl"
        if ledger_path.is_file():
            for line in ledger_path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("id") == ref:
                    return {"kind": "evidence", "ref": ref}
        raise CTFError(f"Unresolved evidence reference {ref}: no E-* record in evidence.jsonl")

    # Otherwise the reference must be an artifact path inside the challenge.
    candidate = Path(ref)
    if not candidate.is_absolute():
        candidate = challenge_dir / candidate
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise CTFError(f"Unresolved evidence reference {ref}: {exc}") from exc
    if not _path_within(challenge_dir, resolved) or not resolved.is_file():
        raise CTFError(
            f"Unresolved evidence reference {ref}: artifact is missing or outside the challenge"
        )
    return {
        "kind": "artifact",
        "ref": ref,
        "path": str(resolved.relative_to(challenge_dir)),
    }


def validate_evidence_refs(
    challenge_dir: Path,
    refs: list[str] | tuple[str, ...] | None,
) -> list[dict[str, str]]:
    """Validate every evidence reference; raises on the first unresolved one."""
    resolved: list[dict[str, str]] = []
    for raw in refs or []:
        ref = str(raw).strip()
        if not ref:
            continue
        resolved.append(resolve_evidence_ref(challenge_dir, ref))
    return resolved


class EvidenceLedger:
    def __init__(self, challenge_dir: Path):
        self.challenge_dir = challenge_dir.resolve()
        self.path = self.challenge_dir / "evidence.jsonl"
        self.markdown_path = self.challenge_dir / "EVIDENCE.md"

    def add(
        self,
        source: str,
        observation: str,
        meaning: str,
        confidence: str = "HIGH",
        classification: str = "FACT",
    ) -> dict[str, Any]:
        confidence = confidence.upper()
        classification = classification.upper()
        if confidence not in {"LOW", "MEDIUM", "HIGH"}:
            raise CTFError("Confidence must be LOW, MEDIUM, or HIGH")
        if classification not in {"FACT", "INFERENCE", "HYPOTHESIS", "UNKNOWN"}:
            raise CTFError("Classification must be FACT, INFERENCE, HYPOTHESIS, or UNKNOWN")
        with challenge_lock(self.challenge_dir, description="evidence.add"):
            record = {
                "id": next_id(self.path, "E"),
                "source": source,
                "observation": observation,
                "meaning": meaning,
                "classification": classification,
                "confidence": confidence,
                "timestamp": utcnow(),
            }
            append_jsonl(self.path, record)
            self.render()
        return record

    def records(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        result = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return result

    def render(self) -> str:
        records = self.records()
        lines = ["# Evidence Ledger", "", "> Generated from `evidence.jsonl`.", ""]
        if not records:
            lines.append("No evidence recorded.")
        for item in records:
            lines.extend(
                [
                    f"## {item['id']}",
                    "",
                    f"- Source: `{item['source']}`",
                    f"- Classification: `{item['classification']}`",
                    f"- Confidence: `{item['confidence']}`",
                    f"- Timestamp: `{item['timestamp']}`",
                    "",
                    f"**Observation:** {item['observation']}",
                    "",
                    f"**Meaning:** {item['meaning']}",
                    "",
                ]
            )
        content = "\n".join(lines)
        atomic_write_text(self.markdown_path, content)
        return content
