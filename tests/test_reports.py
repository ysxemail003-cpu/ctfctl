import json
from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError
from ctf_agent.report import final_report, handoff, merge_result
from ctf_agent.runner import run_command
from ctf_agent.state import StateStore
from ctf_agent.util import sha256_file


def _log(challenge: Path, tag: str) -> str:
    meta = run_command(challenge, ["printf", "ok\n"], tag, "test", quiet=True, force=True)
    return meta["id"]


def _write_result(challenge: Path, result: dict) -> Path:
    path = challenge / "reports" / "result-web.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _base_result(log1: str) -> dict:
    return {
        "schema_version": 2,
        "result_id": "RES-WEB-0001",
        "agent": "ctf-agent-web",
        "status": "PARTIAL",
        "objective": "Map HTTP surface",
        "facts": [{"statement": "Root exists", "evidence": [log1]}],
        "hypotheses": [
            {
                "statement": "Login is vulnerable",
                "test": "Compare inputs",
                "expected": "Different response",
            }
        ],
        "failed_techniques": ["admin:admin"],
        "recommended_next_action": "Diff login responses",
        "risk": "LOW",
        "confidence": "MEDIUM",
    }


def test_handoff_merge_and_final_report(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "report", "web", "AI_NATIVE", confirm_authorization=True)
    handoff_path = handoff(
        challenge,
        "ctf-agent-web",
        "Map HTTP surface",
        ["state.yaml"],
        ["Stay in scope"],
    )
    assert handoff_path.is_file()

    log1 = _log(challenge, "root")
    result_path = _write_result(challenge, _base_result(log1))
    merged = merge_result(challenge, result_path)
    assert merged["merged"] is True
    assert merged["added"]["facts"] == ["F-0001"]
    assert merged["added"]["hypotheses"] == ["H-0001"]
    assert merged["source_hash"] == sha256_file(result_path)

    state = StateStore(challenge).load()
    assert state["facts"][0]["evidence"] == [log1]
    assert state["next_action"] == "Diff login responses"

    report = final_report(
        challenge,
        root_cause="Weak authentication",
        attack_path=["Recon", "Bypass"],
        exploit="scripts/solve.py",
        verification="Reproduced twice",
        lessons=["Validate identity server-side"],
    )
    assert report.is_file()
    assert "Weak authentication" in report.read_text(encoding="utf-8")


def test_merge_is_idempotent(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "idem", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "root")
    result_path = _write_result(challenge, _base_result(log1))

    first = merge_result(challenge, result_path)
    assert first["merged"] is True
    second = merge_result(challenge, result_path)
    assert second["merged"] is False
    assert second["reason"] == "already_merged"
    assert second["result_id"] == "RES-WEB-0001"

    state = StateStore(challenge).load()
    assert len(state["facts"]) == 1
    history = (challenge / "reports" / "merged-results.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(history) == 1


def test_merge_deduplicates_identical_entries_within_one_file(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "dedupe", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "root")
    result = _base_result(log1)
    result["facts"].append({"statement": "Root exists", "evidence": [log1]})
    result_path = _write_result(challenge, result)
    merged = merge_result(challenge, result_path)
    assert merged["added"]["facts"] == ["F-0001"]
    assert len(StateStore(challenge).load()["facts"]) == 1


def test_merge_rejects_invalid_schema_without_partial_state(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "schema", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "root")
    result = _base_result(log1)
    del result["hypotheses"]
    result_path = _write_result(challenge, result)
    with pytest.raises(CTFError):
        merge_result(challenge, result_path)
    assert StateStore(challenge).load()["facts"] == []
    assert not (challenge / "reports" / "merged-results.jsonl").exists()


def test_merge_rejects_unresolved_evidence_without_partial_state(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "badev", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "root")
    result = _base_result(log1)
    result["facts"] = [
        {"statement": "Bad fact", "evidence": ["LOG-999999"]},
        {"statement": "Good fact", "evidence": [log1]},
    ]
    result_path = _write_result(challenge, result)
    with pytest.raises(CTFError) as excinfo:
        merge_result(challenge, result_path)
    assert "LOG-999999" in str(excinfo.value)
    # No partial state modification.
    assert StateStore(challenge).load()["facts"] == []
    assert not (challenge / "reports" / "merged-results.jsonl").exists()


def test_merge_rejects_wrong_source_hash(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "hash", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "root")
    result = _base_result(log1)
    result["source_hash"] = "0" * 64
    result_path = _write_result(challenge, result)
    with pytest.raises(CTFError) as excinfo:
        merge_result(challenge, result_path)
    assert "source_hash" in str(excinfo.value)


def test_old_schema_v1_result_imports_compatibly(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "v1", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "root")
    result = {
        "agent": "ctf-agent-web",
        "status": "PARTIAL",
        "objective": "Map HTTP surface",
        "facts": [{"statement": "Root exists", "evidence": [log1]}],
        "hypotheses": [],
        "failed_techniques": [],
        "recommended_next_action": "Diff login responses",
    }
    result_path = _write_result(challenge, result)
    merged = merge_result(challenge, result_path)
    assert merged["merged"] is True
    assert merged["result_id"].startswith("RES-")
    assert merged["source_hash"] == sha256_file(result_path)
