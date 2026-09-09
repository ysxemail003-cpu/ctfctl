import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ctf_agent.adapters import http as http_adapter
from ctf_agent.adapters import recon as recon_adapter
from ctf_agent.challenge import (
    get_current_challenge,
    init_challenge,
    list_challenges,
    resolve_challenge_selector,
    set_current_challenge,
)
from ctf_agent.context import build_context, render_context_markdown
from ctf_agent.intake import parse_intent
from ctf_agent.state import StateStore


def test_intake_parses_natural_language_web_request():
    intent = parse_intent(
        "比赛 2026-demo，题目 web-login，这是一道 Web 题，"
        "目标 http://challenge.example.ctf，比赛允许 AI 自动解题，"
        "不要自动提交 flag，附件 ~/Downloads/web.zip"
    )
    assert intent["event"] == "2026-demo"
    assert intent["challenge"] == "web-login"
    assert intent["category"] == "web"
    assert intent["mode"] == "AI_NATIVE"
    assert intent["authorization_confirmed"] is True
    assert intent["target"] == "http://challenge.example.ctf"
    assert intent["ports"] == [80]
    assert intent["files"] == ["~/Downloads/web.zip"]
    assert intent["constraints"] == ["no_auto_submit"]
    assert intent["capabilities"]["allow_flag_submission"] is False
    assert intent["missing"] == []


def test_intake_requires_authorization_and_target_for_pwn():
    intent = parse_intent("这是一道 Pwn 题，帮我解，远程端口 1337")
    assert intent["category"] == "pwn"
    assert intent["ports"] == [1337]
    assert "authorization" in intent["missing"]
    assert "target_or_input_file" in intent["missing"]


def test_current_pointer_and_challenge_listing(tmp_path: Path):
    workspace = tmp_path / "workspace"
    challenge = init_challenge(
        workspace,
        "demo-event",
        "pwn easy",
        "pwn",
        "AI_NATIVE",
        target="pwn.example.ctf",
        ports=[1337],
        confirm_authorization=True,
    )
    set_current_challenge(workspace, challenge)
    assert get_current_challenge(workspace) == challenge.resolve()

    items = list_challenges(workspace)
    assert len(items) == 1
    assert items[0]["event"] == "demo-event"
    assert items[0]["challenge"] == "pwn-easy"
    assert items[0]["current"] is True

    assert resolve_challenge_selector(workspace, "pwn-easy") == challenge.resolve()
    assert resolve_challenge_selector(workspace, "demo-event/pwn-easy") == challenge.resolve()


def test_context_compacts_state_evidence_and_logs(tmp_path: Path):
    challenge = init_challenge(
        tmp_path,
        "demo",
        "context",
        "web",
        "AI_NATIVE",
        confirm_authorization=True,
        constraints=["no_auto_submit"],
    )
    from ctf_agent.runner import run_command

    # Create real LOG-* fixtures first so strict evidence references resolve.
    log1 = run_command(challenge, ["printf", "hello\n"], "hello", "test", quiet=True)["id"]
    log2 = run_command(challenge, ["printf", "bye\n"], "bye", "test", quiet=True)["id"]
    store = StateStore(challenge)
    store.add_fact("Root page exists", [log1])
    store.add_hypothesis("Login is injectable", "Compare inputs", "Different response")
    store.add_technique("admin:admin", "failed", [log2])
    store.set_next("Diff login responses")

    context = build_context(challenge)
    assert context["status"] == "AUTHORIZED"
    assert context["operator_constraints"] == ["no_auto_submit"]
    assert context["facts"][0]["statement"] == "Root page exists"
    assert context["open_hypotheses"][0]["id"] == "H-0001"
    assert context["failed_techniques"][0]["technique"] == "admin:admin"
    assert context["recent_logs"][0]["id"] == log2
    assert context["recent_logs"][1]["id"] == log1

    markdown = render_context_markdown(context)
    assert "Root page exists" in markdown
    assert "Diff login responses" in markdown
    assert "no_auto_submit" in markdown
    assert log1 in markdown
    assert log2 in markdown


def test_web_inventory_parses_forms_and_robots(tmp_path: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /admin\n"
                content_type = "text/plain"
            elif self.path == "/sitemap.xml":
                body = b"<urlset></urlset>"
                content_type = "application/xml"
            else:
                body = b"<html><head><title>Login</title></head><body><form action='/login' method='POST'><input name='username'><input name='password' type='password'></form><a href='/about'>About</a></body></html>"
                content_type = "text/html"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        challenge = init_challenge(tmp_path, "demo", "inventory", "web", "AI_NATIVE", confirm_authorization=True)
        from ctf_agent.scope import ScopeStore

        port = server.server_address[1]
        ScopeStore(challenge).add_host("127.0.0.1", [port])
        result = http_adapter.inventory(challenge, f"http://127.0.0.1:{port}/")
        assert result["requests"][0]["title"] == "Login"
        assert result["forms"][0]["action"] == "/login"
        assert any(field["name"] == "username" for field in result["forms"][0]["fields"])
        assert result["robots_status"] == 200
        assert "Disallow: /admin" in result["robots_directives"]
        assert "http://127.0.0.1:%d/about" % port in result["links"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_file_recon_adapter_structures_file_facts(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "file", "misc", "AI_NATIVE", confirm_authorization=True)
    input_path = tmp_path / "input.txt"
    input_path.write_text("hello flag{not-yet}\n", encoding="utf-8")
    result = recon_adapter.file_recon(challenge, input_path)
    assert result["kind"] == "file"
    assert result["sha256"]
    assert result["logs"]["file"].startswith("LOG-")
    assert any("flag{not-yet}" in line for line in result["interesting_strings"])
    assert (challenge / "artifacts" / "recon" / "input.txt.json").is_file()


def test_nmap_adapter_parses_scoped_xml(tmp_path: Path, monkeypatch):
    import os

    from ctf_agent.adapters import nmap as nmap_adapter
    from ctf_agent.scope import ScopeStore

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_nmap = bin_dir / "nmap"
    fake_nmap.write_text(
        """#!/usr/bin/env python3
import sys
args = sys.argv[1:]
output = args[args.index('-oX') + 1]
target = args[-1]
xml = f'''<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="TestServer" version="1.0"/></port></ports></host></nmaprun>'''
open(output, 'w', encoding='utf-8').write(xml)
""",
        encoding="utf-8",
    )
    fake_nmap.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))

    challenge = init_challenge(tmp_path, "demo", "nmap", "web", "AI_NATIVE", confirm_authorization=True)
    ScopeStore(challenge).add_host("127.0.0.1", [80])
    result = nmap_adapter.scan(challenge, "127.0.0.1", [80], service_detection=True)
    assert result["ports_requested"] == [80]
    assert result["open_ports"][0]["port"] == 80
    assert result["open_ports"][0]["service"] == "http"
    assert result["hosts"][0]["hostnames"] == ["localhost"]
    assert (challenge / result["xml_file"]).is_file()


def test_import_files_preserves_original_inputs(tmp_path: Path):
    from ctf_agent.adapters.ingest import import_files

    challenge = init_challenge(tmp_path, "demo", "import", "misc", "AI_NATIVE", confirm_authorization=True)
    source = tmp_path / "challenge.zip"
    source.write_bytes(b"fake archive")
    result = import_files(challenge, [source], perform_recon=True)
    destination = challenge / "original" / "challenge.zip"
    assert result["count"] == 1
    assert destination.read_bytes() == b"fake archive"
    assert result["imported"][0]["sha256"]
    assert result["imported"][0]["recon"]["kind"] == "file"

    # A second import with the same content is idempotent and never overwrites.
    repeat = import_files(challenge, [source], perform_recon=False)
    assert repeat["imported"][0]["copied"] is False
    assert destination.read_bytes() == b"fake archive"
