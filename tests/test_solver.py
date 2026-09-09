"""Solve-loop engine tests (deterministic ScriptedPolicy / fake backend)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_agent import solver as solver_module
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError

FLAG_REV = b"flag{xor_file_rev}"


class FakeBackend:
    name = "fake"

    def __init__(self, replies: list[str]):
        self.replies = list(replies)

    def available(self) -> bool:
        return True

    def complete(self, prompt: str, timeout: float = 300.0) -> str:
        if not self.replies:
            return ""
        return self.replies.pop(0)


def _challenge(tmp_path: Path, name: str = "solve", category: str = "rev") -> Path:
    challenge = init_challenge(tmp_path, "demo", name, category, "AI_NATIVE", confirm_authorization=True)
    secret = challenge / "original" / "secret.bin"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_bytes(bytes(b ^ 0x42 for b in FLAG_REV))
    return challenge


def _xor_print_code() -> str:
    return (
        "import pathlib;"
        "d=pathlib.Path('original/secret.bin').read_bytes();"
        "print(bytes(b^0x42 for b in d).decode())"
    )


# --- JSON extraction ---


def test_extract_json_object_fenced():
    text = 'ok\n```json\n{"analysis": "a", "flag_candidate": null}\n```\n'
    assert solver_module.extract_json_object(text)["analysis"] == "a"


def test_extract_json_object_prose_and_invalid():
    assert solver_module.extract_json_object('here: {"commands": [], "analysis": "x"} trailing')["commands"] == []
    assert solver_module.extract_json_object("no json here") is None


def test_sanitize_argv_rejects_bad_roots():
    with pytest.raises(CTFError):
        solver_module._sanitize_argv(["rm", "-rf", "/"])
    with pytest.raises(CTFError):
        solver_module._sanitize_argv(["run", "--tag", "x" * 1000])


# --- engine end-to-end ---


def test_solve_solved_via_detected_flag(tmp_path: Path):
    challenge = _challenge(tmp_path)
    policy = solver_module.ScriptedPolicy(
        responses=[{"analysis": "xor the bytes", "commands": [["run", "--tag", "xor", "--", "python3", "-c", _xor_print_code()]], "flag_candidate": None, "conclusion": None}]
    )
    summary = solver_module.run_solve(challenge, policy=policy, max_rounds=3)
    assert summary.status == "SOLVED"
    assert summary.flag == FLAG_REV.decode()
    assert summary.rounds == 1
    round_dir = challenge / "agent_rounds" / "round-01"
    assert (round_dir / "prompt.md").is_file()
    assert (round_dir / "response.json").is_file()
    assert (challenge / "agent_rounds" / "summary.json").is_file()
    # flag recorded through the canonical flag candidate API
    candidates = [json.loads(line) for line in (challenge / "flags" / "candidates.jsonl").read_text().splitlines() if line.strip()]
    assert candidates and candidates[-1]["value"] == FLAG_REV.decode()


def test_solve_solved_via_model_flag_candidate(tmp_path: Path):
    challenge = _challenge(tmp_path, "solve-candidate")
    policy = solver_module.ScriptedPolicy(
        responses=[{"analysis": "plain", "commands": [], "flag_candidate": FLAG_REV.decode(), "conclusion": None}]
    )
    summary = solver_module.run_solve(challenge, policy=policy, max_rounds=3)
    assert summary.status == "SOLVED"
    assert summary.flag == FLAG_REV.decode()


def test_solve_stuck_on_no_activity(tmp_path: Path):
    challenge = _challenge(tmp_path, "solve-stuck")

    def generator(round_index: int, prompt: str):
        return {"analysis": "nothing new", "commands": [], "flag_candidate": None, "conclusion": None}

    summary = solver_module.run_solve(
        challenge, policy=solver_module.ScriptedPolicy(generator=generator), max_rounds=4
    )
    assert summary.status == "STUCK"
    assert summary.reason and ("no new evidence" in summary.reason or "max rounds" in summary.reason)


def test_solve_stuck_on_conclusion(tmp_path: Path):
    challenge = _challenge(tmp_path, "solve-concl")

    def generator(round_index: int, prompt: str):
        return {"analysis": "gave up", "commands": [], "flag_candidate": None, "conclusion": "stuck"}

    summary = solver_module.run_solve(
        challenge, policy=solver_module.ScriptedPolicy(generator=generator), max_rounds=4
    )
    assert summary.status == "STUCK"
    assert summary.reason == "policy concluded stuck"
    assert summary.rounds == 1


def test_solve_stuck_on_two_invalid_replies(tmp_path: Path):
    challenge = _challenge(tmp_path, "solve-invalid")
    backend = FakeBackend(["this is not json", "still not json"])
    summary = solver_module.run_solve(challenge, backend=backend, max_rounds=4)
    assert summary.status == "STUCK"
    assert "unparseable" in (summary.reason or "")


def test_solve_records_events(tmp_path: Path):
    challenge = _challenge(tmp_path, "solve-events")
    policy = solver_module.ScriptedPolicy(
        responses=[{"analysis": "xor the bytes", "commands": [["run", "--tag", "xor", "--", "python3", "-c", _xor_print_code()]], "flag_candidate": None, "conclusion": None}]
    )
    solver_module.run_solve(challenge, policy=policy, max_rounds=3)
    events = (challenge / "events.jsonl").read_text().splitlines()
    assert any("solve_solved" in line for line in events)


def test_run_solve_requires_challenge(tmp_path: Path):
    with pytest.raises(CTFError):
        solver_module.run_solve(tmp_path / "missing", policy=solver_module.ScriptedPolicy([]))


def test_compose_round_prompt_includes_extra_context(tmp_path: Path):
    challenge = _challenge(tmp_path, "solve-extra")
    prompt = solver_module.compose_round_prompt(challenge, 1, 3, [], extra_context="Target URL: http://127.0.0.1:9/")
    assert "EXTRA CONTEXT" in prompt
    assert "Target URL: http://127.0.0.1:9/" in prompt
