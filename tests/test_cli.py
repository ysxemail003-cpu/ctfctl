from pathlib import Path

from ctf_agent.cli import main


def test_cli_init_run_and_flag_verify(tmp_path: Path, capsys):
    workspace = tmp_path / "workspace"
    assert main([
        "init",
        "--workspace",
        str(workspace),
        "--event",
        "cli-demo",
        "--challenge",
        "cli demo",
        "--category",
        "misc",
        "--mode",
        "AI_NATIVE",
        "--confirm-authorization",
        "--no-current",
    ]) == 0
    challenge = workspace / "contests" / "cli-demo" / "cli-demo"
    capsys.readouterr()

    assert main([
        "--challenge-dir",
        str(challenge),
        "run",
        "--tag",
        "hello",
        "--quiet",
        "--",
        "printf",
        "hello\n",
    ]) == 0
    assert (challenge / "logs" / "000001-hello.json").is_file()

    assert main([
        "--challenge-dir",
        str(challenge),
        "flag",
        "candidate",
        "--value",
        "flag{cli}",
        "--source",
        "manual",
    ]) == 0
    assert main([
        "--challenge-dir",
        str(challenge),
        "flag",
        "verify",
        "--replay",
        "printf 'flag{cli}\\n'",
        "--runs",
        "2",
    ]) == 0

    state_text = (challenge / "state.yaml").read_text(encoding="utf-8")
    assert "REPRODUCED" in state_text
    assert (challenge / "STATE.md").is_file()
