"""CLI command coverage: exercise every handler through ctfctl main()."""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from ctf_agent.cli import main


def _init(tmp_path: Path, name: str = "cli-all", workspace: Path | None = None) -> Path:
    workspace = workspace or (tmp_path / "ws")
    rc = main(
        [
            "init",
            "--workspace",
            str(workspace),
            "--event",
            "demo",
            "--challenge",
            name,
            "--category",
            "web",
            "--mode",
            "AI_NATIVE",
            "--confirm-authorization",
            "--no-current",
        ]
    )
    assert rc == 0
    return workspace / "contests" / "demo" / name


def _log(challenge: Path, tag: str = "one", text: str = "ok\n") -> str:
    rc = main(["-C", str(challenge), "run", "--tag", tag, "--quiet", "--", "printf", text])
    assert rc == 0
    return f"LOG-{int(tag[-1]):06d}" if tag[-1].isdigit() else "LOG-000001"


def test_state_scope_and_evidence_commands(tmp_path: Path, capsys):
    challenge = _init(tmp_path)
    log1 = _log(challenge, "1")

    calls = [
        ["state", "show"],
        ["state", "render"],
        ["state", "fact", "add", "Root exists", "--evidence", log1],
        ["state", "hypothesis", "add", "Login injectable", "--test", "cmp", "--expected", "diff"],
        ["state", "hypothesis", "update", "H-0001", "--status", "CONFIRMED", "--result", "differs"],
        ["state", "technique", "admin:admin", "failed", "--evidence", log1],
        ["state", "constraint", "set", "no_auto_submit"],
        ["state", "constraint", "remove", "no_auto_submit"],
        ["state", "next", "Diff responses", "--objective", "Test login"],
        ["state", "transition", "RECON", "--reason", "recon done", "--evidence", log1],
        ["evidence", "add", "--source", log1, "--observation", "port open", "--meaning", "http"],
        ["evidence", "show"],
    ]
    for args in calls:
        rc = main(["-C", str(challenge), *args])
        assert rc == 0, args
    capsys.readouterr()

    # scope command family
    for args in [
        ["scope", "show"],
        ["scope", "confirm"],
        ["scope", "add-host", "example.ctf", "--port", "80"],
        ["scope", "check", "example.ctf", "--port", "80"],
        ["scope", "allow", "flag-submission"],
    ]:
        rc = main(["-C", str(challenge), *args])
        assert rc == 0, args
    out = capsys.readouterr().out
    assert "example.ctf" in out


def test_flag_and_report_commands(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-flag")
    log1 = _log(challenge, "1")
    flag_file = challenge / "work" / "leak.txt"
    flag_file.write_text("found flag{cli-leak} here\n", encoding="utf-8")

    rc = main(["-C", str(challenge), "flag", "detect"])
    assert rc == 0
    assert "flag{cli-leak}" in capsys.readouterr().out
    rc = main(["-C", str(challenge), "flag", "candidate", "--value", "flag{cli-leak}", "--source", "manual"])
    assert rc == 0

    # handoff + merge-result (real log evidence) + final report
    rc = main(
        ["-C", str(challenge), "handoff", "ctf-agent-web", "--objective", "map", "--input", "state.yaml", "--constraint", "scope"]
    )
    assert rc == 0
    result_path = challenge / "reports" / "result-web.json"
    result_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "agent": "ctf-agent-web",
                "status": "PARTIAL",
                "facts": [{"statement": "Root reachable", "evidence": [log1]}],
                "hypotheses": [],
                "failed_techniques": [],
                "recommended_next_action": "Diff login",
            }
        ),
        encoding="utf-8",
    )
    rc = main(["-C", str(challenge), "merge-result", str(result_path)])
    assert rc == 0
    rc = main(
        [
            "-C", str(challenge), "report", "final",
            "--root-cause", "weak auth",
            "--attack-path", "recon",
            "--exploit", "scripts/solve.py",
            "--verification", "twice",
            "--lesson", "keep evidence",
        ]
    )
    assert rc == 0
    assert "weak auth" in (challenge / "reports" / "final.md").read_text(encoding="utf-8")


def test_tool_file_and_elf_commands(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-tool")
    text = tmp_path / "sample.txt"
    text.write_text("hello world\n", encoding="utf-8")
    for args in [
        ["tool", "file", str(text)],
        ["tool", "elf", "/bin/true"],
    ]:
        rc = main(["-C", str(challenge), *args])
        assert rc == 0, args
    assert "kind" in capsys.readouterr().out


def test_import_files_and_intake(tmp_path: Path, capsys, monkeypatch):
    challenge = _init(tmp_path, "cli-import")
    source = tmp_path / "payload.bin"
    source.write_bytes(b"abc")
    rc = main(["-C", str(challenge), "import-files", str(source)])
    assert rc == 0
    assert (challenge / "original" / "payload.bin").is_file()

    rc = main(["intake", "--text", "web challenge at http://t.ctf authorized AI"])
    assert rc == 0
    assert "web" in capsys.readouterr().out
    rc = main(["intake", "--text", "web challenge", "--markdown"])
    assert rc == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO("pwn challenge 1337 authorized"))
    rc = main(["intake", "--text", "-", "--markdown"])
    assert rc == 0


def test_navigation_commands_with_tmp_repo(tmp_path: Path, capsys, monkeypatch):
    import ctf_agent.commands.admin as admin_mod
    import ctf_agent.commands.challenge_cmds as nav_mod

    repo = tmp_path / "repo"
    monkeypatch.setattr(nav_mod, "ROOT", repo)
    monkeypatch.setattr(admin_mod, "ROOT", repo)
    workspace = repo / "workspace"
    challenge = _init(tmp_path, "nav", workspace=workspace)

    # init keeps current pointer when --no-current is not set; set it via use.
    rc = main(["use", "--workspace", str(workspace), "demo/nav"])
    assert rc == 0
    for args in [
        ["current", "--json"],
        ["current"],
        ["challenges"],
        ["list", "--json"],
    ]:
        rc = main(args)
        assert rc == 0, args
    for args in [
        ["context", "--markdown"],
        ["context"],
        ["status", "--markdown"],
        ["status"],
    ]:
        rc = main(["-C", str(challenge), *args])
        assert rc == 0, args
    out = capsys.readouterr().out
    assert "demo/nav" in out or "nav" in out

    rc = main(["doctor", "--json"])
    assert rc == 0
    rc = main(["doctor"])
    assert rc == 0
    # sync-agents against an empty tmp repo is a safe no-op.
    rc = main(["sync-agents"])
    assert rc == 0


def test_tool_http_inventory_nmap_and_ghidra_error(tmp_path: Path, capsys, monkeypatch):
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /admin\n"
            else:
                body = b"<html><title>Home</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain" if self.path == "/robots.txt" else "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        challenge = _init(tmp_path, "cli-http")
        rc = main(["-C", str(challenge), "scope", "add-host", "127.0.0.1", "--port", str(port)])
        assert rc == 0
        base = f"http://127.0.0.1:{port}"
        rc = main(["-C", str(challenge), "tool", "http", base + "/", "--tag", "root"])
        assert rc == 0
        rc = main(["-C", str(challenge), "tool", "web-inventory", base + "/"])
        assert rc == 0
        assert "Disallow: /admin" in capsys.readouterr().out
    finally:
        server.shutdown()
        server.server_close()

    # fake nmap on PATH so the adapter path executes without the real tool
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "nmap"
    fake.write_text(
        "#!/usr/bin/env python3\nimport sys\n"
        "args = sys.argv[1:]\n"
        "out = args[args.index('-oX') + 1]\n"
        "open(out, 'w').write('<nmaprun><host><address addr=\"127.0.0.1\" addrtype=\"ipv4\"/>"
        "<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\" reason=\"syn-ack\"/>"
        "<service name=\"http\"/></port></ports></host></nmaprun>')\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    challenge2 = _init(tmp_path, "cli-nmap")
    rc = main(["-C", str(challenge2), "scope", "add-host", "127.0.0.1", "--port", "80"])
    assert rc == 0
    rc = main(["-C", str(challenge2), "tool", "nmap", "127.0.0.1", "--port", "80"])
    assert rc == 0
    assert "open_ports" in capsys.readouterr().out

    # ghidra: exit 0 when the tool is installed, else a clear CLI error (2)
    import shutil

    challenge3 = _init(tmp_path, "cli-ghidra")
    installed = shutil.which("analyzeHeadless") is not None or Path(
        "/usr/share/ghidra/support/analyzeHeadless"
    ).is_file()
    rc = main(["-C", str(challenge3), "tool", "ghidra", "/bin/true"])
    assert rc == (0 if installed else 2)
    capsys.readouterr()


def test_flag_submit_dry_run_via_cli(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-submit")
    rc = main(
        ["-C", str(challenge), "flag", "candidate", "--value", "flag{dry}", "--source", "manual"]
    )
    assert rc == 0
    rc = main(
        [
            "-C", str(challenge), "flag", "submit",
            "--url", "http://127.0.0.1:1/api",
            "--challenge-id", "1",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert '"dry_run": true' in out


def test_logs_summary_and_archive(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-logs")
    rc = main(["-C", str(challenge), "run", "--tag", "one", "--quiet", "--", "printf", "a\n"])
    assert rc == 0
    rc = main(["-C", str(challenge), "run", "--tag", "two", "--quiet", "--", "printf", "b\n"])
    assert rc == 0
    rc = main(["-C", str(challenge), "logs", "summary"])
    assert rc == 0
    assert '"log_count": 2' in capsys.readouterr().out
    rc = main(["-C", str(challenge), "logs", "archive", "--dry-run"])
    assert rc == 0
    assert '"dry_run": true' in capsys.readouterr().out
    rc = main(["-C", str(challenge), "logs", "archive"])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"moved_count": 2' in out
    assert (challenge / "logs" / "archive").is_dir()
