"""Benchmark harness unit tests (self-contained, no external tools)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_agent import bench as bench_module
from ctf_agent.errors import CTFError
from ctf_agent.solver import ScriptedPolicy


def _write_challenge(
    root: Path,
    challenge_id: str,
    flag: str = "flag{test}",
    requires: list[str] | None = None,
    target: bool = False,
    driver: str = 'print("FLAG=flag{test}")',
) -> Path:
    challenge_dir = root / "misc" / challenge_id
    challenge_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "id": challenge_id,
        "category": "misc",
        "difficulty": "easy",
        "title": challenge_id,
        "description": "",
        "flag": flag,
        "driver": "script",
        "solve": "solve.py",
        "requires": requires or [],
        "target": target,
    }
    (challenge_dir / "challenge.json").write_text(json.dumps(manifest), encoding="utf-8")
    (challenge_dir / "solve.py").write_text(
        "import sys, argparse\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--challenge-dir', type=Path if False else str, required=True)\n"
        "parser.add_argument('--root', required=True)\n"
        "parser.add_argument('--ctfctl', required=True)\n"
        f"{driver}\n",
        encoding="utf-8",
    )
    return challenge_dir


def _suite(root: Path) -> Path:
    suite = root / "suite"
    suite.mkdir(parents=True, exist_ok=True)
    return suite


def test_discover_suite_parses_manifest(tmp_path: Path):
    challenge_dir = _write_challenge(_suite(tmp_path), "one")
    found = bench_module.discover_suite(challenge_dir.parent)
    assert len(found) == 1
    assert found[0].id == "one"
    assert found[0].flag == "flag{test}"


def test_discover_suite_requires_manifest_fields(tmp_path: Path):
    suite = _suite(tmp_path)
    bad = suite / "misc" / "bad"
    bad.mkdir(parents=True, exist_ok=True)
    (bad / "challenge.json").write_text('{"id": "bad"}', encoding="utf-8")
    with pytest.raises(CTFError):
        bench_module.discover_suite(suite)


def test_run_challenge_solved(tmp_path: Path):
    suite = _suite(tmp_path)
    _write_challenge(suite, "ok", driver='print("FLAG=flag{test}")')
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "SOLVED"
    assert result["flag_matched"] is True
    assert result["actions"] >= 0


def test_run_challenge_failed_on_wrong_flag(tmp_path: Path):
    suite = _suite(tmp_path)
    _write_challenge(suite, "wrong", driver='print("FLAG=flag{other}")')
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "FAILED"
    assert "mismatch" in (result.get("reason") or "")


def test_run_challenge_failed_no_flag(tmp_path: Path):
    suite = _suite(tmp_path)
    _write_challenge(suite, "noflag", driver="print('nothing here')")
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "FAILED"
    assert "no FLAG" in (result.get("reason") or "")


def test_run_challenge_error_on_nonzero_exit(tmp_path: Path):
    suite = _suite(tmp_path)
    _write_challenge(suite, "crash", driver="raise SystemExit(3)")
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "ERROR"


def test_run_challenge_skipped_when_tool_missing(tmp_path: Path):
    suite = _suite(tmp_path)
    _write_challenge(suite, "skip", requires=["definitely-not-installed-tool-xyz"])
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "SKIPPED"
    assert "definitely-not-installed-tool-xyz" in (result.get("reason") or "")


def test_run_suite_writes_artifacts_and_filters(tmp_path: Path):
    suite = _suite(tmp_path)
    _write_challenge(suite, "ok", driver='print("FLAG=flag{test}")')
    _write_challenge(suite, "skip", requires=["definitely-not-installed-tool-xyz"])
    out = tmp_path / "results"
    summary = bench_module.run_suite(suite_dir=suite, out_dir=out)
    assert summary["total"] == 2
    assert summary["counts"]["SOLVED"] == 1
    assert summary["counts"]["SKIPPED"] == 1
    run_dir = Path(summary["run_dir"])
    assert (run_dir / "summary.json").is_file()
    assert (run_dir / "failure_modes.json").is_file()
    assert (run_dir / "REPORT.md").is_file()

    only = bench_module.run_suite(suite_dir=suite, out_dir=tmp_path / "results2", only="ok")
    assert only["total"] == 1


def test_run_challenge_target_server(tmp_path: Path):
    suite = _suite(tmp_path)
    driver = (
        "import urllib.request\n"
        "import argparse, sys\n"
        "p = argparse.ArgumentParser()\n"
        "p.add_argument('--challenge-dir'); p.add_argument('--root'); p.add_argument('--ctfctl')\n"
        "p.add_argument('--target-url', required=True)\n"
        "a = p.parse_args()\n"
        "resp = urllib.request.urlopen(a.target_url)\n"
        "print('FLAG=' + resp.headers['X-Bench-Flag'])\n"
    )
    _write_challenge(suite, "web", flag="flag{header}", target=True, driver=driver)
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "SOLVED"
    assert result["flag_matched"] is True



XOR_FLAG = "flag{xor_file_rev}"
XOR_CODE = (
    "import pathlib;"
    "d=pathlib.Path('original/secret.bin').read_bytes();"
    "print(bytes(b^0x42 for b in d).decode())"
)


def _write_solver_challenge(root: Path, challenge_id: str = "xor-solver") -> Path:
    suite = root / "suite"
    challenge_dir = suite / "rev" / challenge_id
    challenge_dir.mkdir(parents=True, exist_ok=True)
    (challenge_dir / "original").mkdir(parents=True, exist_ok=True)
    (challenge_dir / "original" / "secret.bin").write_bytes(bytes(b ^ 0x42 for b in XOR_FLAG.encode()))
    manifest = {
        "schema_version": 1,
        "id": challenge_id,
        "category": "rev",
        "difficulty": "easy",
        "title": challenge_id,
        "description": "",
        "flag": XOR_FLAG,
        "driver": "solver",
        "solve": "solve.py",
        "requires": [],
        "target": False,
    }
    (challenge_dir / "challenge.json").write_text(json.dumps(manifest), encoding="utf-8")
    (challenge_dir / "solve.py").write_text("print('FLAG=' + 'unused')\n", encoding="utf-8")
    return suite


def _xor_response(round_index: int, prompt: str) -> dict:
    return {
        "analysis": "undo single-byte xor",
        "commands": [["run", "--tag", "xor", "--", "python3", "-c", XOR_CODE]],
        "flag_candidate": None,
        "conclusion": None,
    }


def test_run_challenge_solver_driver_solved(tmp_path: Path):
    suite = _write_solver_challenge(tmp_path)
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(
        challenge, tmp_path / "out", driver="solver", policy=ScriptedPolicy(generator=_xor_response)
    )
    assert result["status"] == "SOLVED"
    assert result["flag_matched"] is True
    assert result["rounds"] == 1
    assert result["actions"] >= 1


def test_run_challenge_solver_driver_stuck_is_failed(tmp_path: Path):
    suite = _write_solver_challenge(tmp_path, "xor-stuck")
    challenge = bench_module.discover_suite(suite)[0]

    def stuck(round_index: int, prompt: str) -> dict:
        return {"analysis": "nothing", "commands": [], "flag_candidate": None, "conclusion": None}

    result = bench_module.run_challenge(
        challenge, tmp_path / "out", driver="solver", policy=ScriptedPolicy(generator=stuck), max_rounds=3
    )
    assert result["status"] == "FAILED"
    assert result["reason"]


def test_run_challenge_solver_driver_requires_backend_or_policy(tmp_path: Path):
    suite = _write_solver_challenge(tmp_path, "xor-nobackend")
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out", driver="solver")
    assert result["status"] == "SKIPPED"
    assert "solver driver requires" in (result.get("reason") or "")


def test_run_suite_solver_driver_with_policy(tmp_path: Path):
    suite = _write_solver_challenge(tmp_path, "xor-suite")
    summary = bench_module.run_suite(
        suite_dir=suite,
        out_dir=tmp_path / "results",
        driver="solver",
        policy=ScriptedPolicy(generator=_xor_response),
    )
    assert summary["counts"]["SOLVED"] == 1
    assert summary["counts"]["FAILED"] == 0



def test_run_challenge_login_target_server(tmp_path: Path):
    suite = tmp_path / "suite"
    challenge_dir = suite / "web" / "login"
    challenge_dir.mkdir(parents=True, exist_ok=True)
    (challenge_dir / "challenge.json").write_text(
        json.dumps({
            "schema_version": 1,
            "id": "login",
            "category": "web",
            "difficulty": "medium",
            "title": "login",
            "description": "",
            "flag": "flag{login}",
            "driver": "script",
            "solve": "solve.py",
            "requires": [],
            "target": True,
            "server": "login",
            "server_creds": {"username": "admin", "password": "hunter2"},
        }),
        encoding="utf-8",
    )
    driver = (
        "import urllib.request, urllib.parse, argparse\n"
        "p = argparse.ArgumentParser()\n"
        "p.add_argument('--challenge-dir'); p.add_argument('--root'); p.add_argument('--ctfctl')\n"
        "p.add_argument('--target-url', required=True)\n"
        "a = p.parse_args()\n"
        "data = urllib.parse.urlencode({'user': 'admin', 'pass': 'hunter2'}).encode()\n"
        "req = urllib.request.Request(a.target_url.rstrip('/') + '/login', data=data, method='POST')\n"
        "resp = urllib.request.urlopen(req)\n"
        "print('FLAG=' + resp.headers['X-Bench-Flag'])\n"
    )
    (challenge_dir / "solve.py").write_text(driver, encoding="utf-8")
    challenge = bench_module.discover_suite(suite)[0]
    result = bench_module.run_challenge(challenge, tmp_path / "out")
    assert result["status"] == "SOLVED"
    assert result["flag_matched"] is True



def test_run_suite_parallel(tmp_path: Path):
    suite = _suite(tmp_path)
    for index in range(3):
        _write_challenge(suite, f"p{index}", driver='print("FLAG=flag{test}")')
    summary = bench_module.run_suite(suite_dir=suite, out_dir=tmp_path / "results", parallel=3)
    assert summary["total"] == 3
    assert summary["counts"]["SOLVED"] == 3
    assert summary["counts"]["FAILED"] == 0
