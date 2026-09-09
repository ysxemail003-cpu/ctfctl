from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import CTFError

from .util import append_jsonl, atomic_write_text, next_id, utcnow


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
