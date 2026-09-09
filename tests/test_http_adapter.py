import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ctf_agent.adapters.http import request
from ctf_agent.challenge import init_challenge
from ctf_agent.scope import ScopeStore


def test_http_adapter_saves_artifacts(tmp_path: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><title>CTF</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        challenge = init_challenge(tmp_path, "demo", "http", "web", "AI_NATIVE", confirm_authorization=True)
        ScopeStore(challenge).add_host("127.0.0.1", [port])
        result = request(challenge, f"http://127.0.0.1:{port}/", tag="root")
        assert result["status"] == 200
        assert result["title"] == "CTF"
        assert (challenge / result["body_file"]).read_bytes().startswith(b"<html>")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_redirect_to_unauthorized_port_is_rejected(tmp_path: Path):
    from ctf_agent.errors import CTFError

    class OriginHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target_port}/leaked")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    origin = HTTPServer(("127.0.0.1", 0), OriginHandler)
    target = HTTPServer(("127.0.0.1", 0), TargetHandler)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (origin, target)
    ]
    for thread in threads:
        thread.start()
    target_port = target.server_address[1]
    try:
        challenge = init_challenge(tmp_path, "demo", "redirect", "web", "AI_NATIVE", confirm_authorization=True)
        ScopeStore(challenge).add_host("127.0.0.1", [origin.server_address[1]])
        try:
            request(challenge, f"http://127.0.0.1:{origin.server_address[1]}/redirect")
        except CTFError as exc:
            assert "not authorized" in str(exc)
        else:
            raise AssertionError("expected redirect scope rejection")
    finally:
        for server in (origin, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)
