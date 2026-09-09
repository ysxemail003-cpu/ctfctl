"""Trajectory export tests."""
from __future__ import annotations

import json
from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.evidence import EvidenceLedger
from ctf_agent.runner import run_command
from ctf_agent.solver import ScriptedPolicy, run_solve
from ctf_agent.trajectory import export_trajectory

XOR_FLAG = "flag{trajectory_check}"
XOR_CODE = (
    "import pathlib;"
    "d=pathlib.Path('original/secret.bin').read_bytes();"
    "print(bytes(b^0x42 for b in d).decode())"
)


def _challenge(tmp_path: Path) -> Path:
    challenge = init_challenge(tmp_path, "demo", "traj", "rev", "AI_NATIVE", confirm_authorization=True)
    secret = challenge / "original" / "secret.bin"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(bytes(b ^ 0x42 for b in XOR_FLAG.encode()))
    return challenge


def test_export_trajectory_aggregates_trail(tmp_path: Path):
    challenge = _challenge(tmp_path)
    # logged action
    log = run_command(challenge, ["printf", "probe-output"], "probe", quiet=True)
    # evidence record
    EvidenceLedger(challenge).add(source=log["id"], observation="binary prints probe-output", meaning="behavior baseline")
    # agent rounds (solver solved)
    policy = ScriptedPolicy(
        responses=[{"analysis": "xor decode", "commands": [["run", "--tag", "xor", "--", "python3", "-c", XOR_CODE]], "flag_candidate": None, "conclusion": None}]
    )
    solve = run_solve(challenge, policy=policy, max_rounds=3)
    assert solve.status == "SOLVED"

    record = export_trajectory(challenge)
    assert record["schema_version"] == 1
    assert record["challenge"]["name"] == "traj"
    assert record["final_flag"] == XOR_FLAG
    assert record["summary"]["action_count"] >= 2  # probe + solver action
    assert record["summary"]["agent_round_count"] == 1
    assert record["summary"]["evidence_count"] == 1

    kinds = {item["kind"] for item in record["trajectory"]}
    assert {"action", "agent_round", "evidence"} <= kinds
    assert any(item["kind"] == "action" and item["log"] == log["id"] for item in record["trajectory"])

    # persisted outputs
    assert record["outputs"]["json"].endswith("trajectory-traj.json")
    assert record["outputs"]["markdown"].endswith("trajectory-traj.md")
    json_path = challenge / record["outputs"]["json"]
    markdown_path = challenge / record["outputs"]["markdown"]
    assert json_path.is_file()
    assert markdown_path.is_file()
    parsed = json.loads(json_path.read_text())
    assert parsed["final_flag"] == XOR_FLAG
    assert "trajectory" in markdown_path.read_text()


def test_export_trajectory_requires_challenge(tmp_path: Path):
    import pytest

    from ctf_agent.errors import CTFError

    with pytest.raises(CTFError):
        export_trajectory(tmp_path / "missing")
