"""Knowledge ledger + review tests (Phase G)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf_agent import knowledge as knowledge_module
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError
from ctf_agent.runner import run_command
from ctf_agent.solver import compose_round_prompt
from ctf_agent.state import StateStore

CATEGORY = "REV"


def _challenge(workspace: Path, name: str = "rev-a") -> Path:
    return init_challenge(workspace, "demo", name, "rev", "AI_NATIVE", confirm_authorization=True)


def _log(challenge: Path) -> str:
    return run_command(challenge, ["printf", "probe"], "probe", quiet=True)["id"]


def test_add_entry_requires_evidence(tmp_path: Path):
    challenge = _challenge(tmp_path, "rev-noevidence")
    with pytest.raises(CTFError, match="evidence reference"):
        knowledge_module.add_entry(
            challenge,
            category=CATEGORY,
            technique="scan binary for xor blobs",
            trigger="similar rev challenge",
            conclusion="blobs live in .rodata",
            outcome="successful",
            evidence_refs=[],
        )
    with pytest.raises(CTFError, match="Unresolved evidence"):
        knowledge_module.add_entry(
            challenge,
            category=CATEGORY,
            technique="x",
            trigger="y",
            conclusion="z",
            outcome="successful",
            evidence_refs=["LOG-999999"],
        )


def test_add_entry_rejects_flag_like_content(tmp_path: Path):
    challenge = _challenge(tmp_path, "rev-flaglike")
    log = _log(challenge)
    with pytest.raises(CTFError, match="not answers"):
        knowledge_module.add_entry(
            challenge,
            category=CATEGORY,
            technique="flag{leak}",
            trigger="t",
            conclusion="c",
            outcome="successful",
            evidence_refs=[log],
        )


def test_add_list_and_match(tmp_path: Path):
    challenge = _challenge(tmp_path, "rev-add")
    log = _log(challenge)
    entry = knowledge_module.add_entry(
        challenge,
        category=CATEGORY,
        technique="xor 0x42 the secret bytes",
        trigger="secret.bin present",
        conclusion="single-byte xor with constant key",
        outcome="successful",
        evidence_refs=[log],
    )
    assert entry["id"].startswith("K-")
    assert entry["outcome"] == "successful"
    ledger = tmp_path / "knowledge.jsonl"
    assert ledger.is_file()

    entries = knowledge_module.list_entries(tmp_path, category="rev")
    assert len(entries) == 1
    assert entries[0]["technique"] == "xor 0x42 the secret bytes"
    assert knowledge_module.list_entries(tmp_path, outcome="failed") == []

    matches = knowledge_module.match_entries(challenge, "rev", limit=3)
    assert matches and matches[0]["id"] == entry["id"]


def test_propose_from_workspace_uses_recorded_techniques(tmp_path: Path):
    challenge = _challenge(tmp_path, "rev-record")
    log = _log(challenge)
    StateStore(challenge).add_technique("strings is enough", "successful", evidence=[log])
    proposals = knowledge_module.propose_from_workspace(tmp_path)
    assert proposals
    assert proposals[0]["outcome"] == "successful"
    assert proposals[0]["evidence_refs"] == [log]
    # ledger itself stays empty until the operator commits
    assert not (tmp_path / "knowledge.jsonl").is_file() or knowledge_module.list_entries(tmp_path) == []


def test_stats_scan(tmp_path: Path):
    challenge = _challenge(tmp_path, "rev-stats")
    log = _log(challenge)
    knowledge_module.add_entry(
        challenge, category=CATEGORY, technique="readelf dyn imports",
        trigger="shared pwn", conclusion="imports reveal libc usage",
        outcome="successful", evidence_refs=[log],
    )
    result = knowledge_module.stats(tmp_path)
    assert result["total"] == 1
    assert result["scan"] == "ok"
    assert result["by_outcome"] == {"successful": 1}


def test_review_writes_markdown(tmp_path: Path):
    challenge = _challenge(tmp_path, "rev-review")
    log = _log(challenge)
    StateStore(challenge).add_technique("brute force too slow", "failed", evidence=[log])
    result = knowledge_module.generate_review(challenge)
    output = challenge / result["output"]
    assert output.is_file()
    text = output.read_text()
    assert "rev-review" in text
    assert "brute force too slow" in text


def test_solver_prompt_injects_knowledge(tmp_path: Path):
    source = _challenge(tmp_path, "rev-source")
    log = _log(source)
    knowledge_module.add_entry(
        source,
        category=CATEGORY,
        technique="xor the whole file once",
        trigger="xor-file challenge with tiny input",
        conclusion="single-byte xor is position independent",
        outcome="successful",
        evidence_refs=[log],
    )
    target = _challenge(tmp_path, "rev-target")
    prompt = compose_round_prompt(target, 1, 4, [])
    assert "KNOWLEDGE (from previous challenges" in prompt
    assert "xor the whole file once" in prompt
    # ledger contains no flag-like content end to end
    raw = (tmp_path / "knowledge.jsonl").read_text().lower()
    assert "flag{" not in raw
