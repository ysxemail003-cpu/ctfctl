import json
from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.runner import run_command


def test_run_command_records_metadata_and_caches(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "runner", "misc", "AI_NATIVE", confirm_authorization=True)
    first = run_command(challenge, ["printf", "hello\n"], "hello", "test", quiet=True)
    assert first["exit_code"] == 0
    assert first["stdout_size"] == 6

    metadata_path = challenge / first["stdout_file"]
    assert metadata_path.read_text(encoding="utf-8") == "hello\n"

    saved = json.loads((challenge / "logs" / "000001-hello.json").read_text(encoding="utf-8"))
    assert saved["command"] == ["printf", "hello\n"]
    assert saved["stdout_sha256"]
    assert saved["exit_code"] == 0

    second = run_command(challenge, ["printf", "hello\n"], "hello", "test", quiet=True)
    assert second["cache_hit"] is True
    assert second["id"] == first["id"]

    third = run_command(challenge, ["printf", "hello\n"], "hello", "test", quiet=True, force=True)
    assert third["id"] != first["id"]


def test_network_tool_requires_explicit_scope(tmp_path: Path):
    from ctf_agent.challenge import init_challenge
    from ctf_agent.runner import run_command

    challenge = init_challenge(tmp_path, "demo", "net", "web", "AI_NATIVE", confirm_authorization=True)
    try:
        run_command(challenge, ["curl", "http://example/"], "curl", "web", quiet=True)
    except Exception as exc:
        assert "network tool" in str(exc)
    else:
        raise AssertionError("expected network guard failure")


def test_scoped_nmap_cannot_scan_unauthorized_port(tmp_path: Path):
    from ctf_agent.challenge import init_challenge
    from ctf_agent.runner import run_command

    challenge = init_challenge(tmp_path, "demo", "nmap", "web", "AI_NATIVE", confirm_authorization=True)
    from ctf_agent.scope import ScopeStore

    ScopeStore(challenge).add_host("allowed.example", [80])
    command = ["nmap", "-Pn", "-sV", "-p", "80,443", "allowed.example"]
    try:
        run_command(
            challenge,
            command,
            "nmap",
            "web-recon",
            network=True,
            target="allowed.example",
            port=80,
            quiet=True,
        )
    except Exception as exc:
        assert "443 is not authorized" in str(exc)
    else:
        raise AssertionError("expected nmap port scope rejection")


def test_generic_network_command_requires_declared_port(tmp_path: Path):
    from ctf_agent.challenge import init_challenge
    from ctf_agent.runner import run_command
    from ctf_agent.scope import ScopeStore

    challenge = init_challenge(tmp_path, "demo", "exploit", "pwn", "AI_NATIVE", confirm_authorization=True)
    ScopeStore(challenge).add_host("allowed.example", [1337])
    try:
        run_command(
            challenge,
            ["python3", "scripts/exploit.py"],
            "remote-exploit",
            "exploitation",
            network=True,
            target="allowed.example",
            quiet=True,
        )
    except Exception as exc:
        assert "specific port is required" in str(exc)
    else:
        raise AssertionError("expected missing-port rejection")


def test_command_cache_includes_input_content_and_network_context(tmp_path: Path):
    from ctf_agent.challenge import init_challenge
    from ctf_agent.runner import run_command
    from ctf_agent.scope import ScopeStore

    challenge = init_challenge(tmp_path, "demo", "cache", "misc", "AI_NATIVE", confirm_authorization=True)
    ScopeStore(challenge).add_host("one.example", [1337])
    ScopeStore(challenge).add_host("two.example", [1337])
    input_file = challenge / "work" / "input.txt"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    input_file.write_text("first\n", encoding="utf-8")

    first = run_command(challenge, ["cat"], "cat", "test", quiet=True, input_file=input_file)
    assert first["exit_code"] == 0
    input_file.write_text("second\n", encoding="utf-8")
    changed = run_command(challenge, ["cat"], "cat", "test", quiet=True, input_file=input_file)
    assert changed.get("cache_hit") is not True
    assert (challenge / changed["stdout_file"]).read_text(encoding="utf-8") == "second\n"

    script = challenge / "scripts" / "solve.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("print('script-one')\n", encoding="utf-8")
    run_command(challenge, ["python3", "scripts/solve.py"], "script-one", "test", quiet=True)
    script.write_text("print('script-two')\n", encoding="utf-8")
    changed_script = run_command(
        challenge,
        ["python3", "scripts/solve.py"],
        "script-two",
        "test",
        quiet=True,
    )
    assert changed_script.get("cache_hit") is not True
    assert (challenge / changed_script["stdout_file"]).read_text(encoding="utf-8") == "script-two\n"

    one = run_command(
        challenge,
        ["python3", "-c", "print('target')"],
        "context-one",
        "test",
        quiet=True,
        network=True,
        target="one.example",
        port=1337,
    )
    two = run_command(
        challenge,
        ["python3", "-c", "print('target')"],
        "context-two",
        "test",
        quiet=True,
        network=True,
        target="two.example",
        port=1337,
    )
    assert one.get("cache_hit") is not True
    assert two.get("cache_hit") is not True
    assert two["id"] != one["id"]
    assert two["scope_check"]["host"] == "two.example"
