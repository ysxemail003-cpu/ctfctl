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


# --------------------------------------------------------------------------- #
# Developer E: cookie sessions + replay
# --------------------------------------------------------------------------- #
def _serve(handler_cls):
    import threading
    from http.server import HTTPServer

    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class AuthHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if self.path == "/login":
            body = b"login ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=sekret-cookie-value; Path=/")
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/profile":
            cookie = self.headers.get("Cookie", "")
            if "session=sekret-cookie-value" in cookie:
                body = b"<html><title>Profile</title></html>"
                content_type = "text/html"
                status = 200
            else:
                body = b"unauthorized"
                content_type = "text/plain"
                status = 401
        else:
            body = b"ok"
            content_type = "text/plain"
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def test_http_session_login_then_continue_and_replay(tmp_path: Path):
    import json as _json

    from ctf_agent.adapters.http import replay_session, session_info

    server, thread = _serve(AuthHandler)
    try:
        port = server.server_address[1]
        challenge = init_challenge(tmp_path, "demo", "session", "web", "AI_NATIVE", confirm_authorization=True)
        ScopeStore(challenge).add_host("127.0.0.1", [port])
        base = f"http://127.0.0.1:{port}"

        login = request(challenge, f"{base}/login", method="POST", data="user=admin&password=x", session="web")
        assert login["status"] == 200
        profile = request(challenge, f"{base}/profile", session="web")
        assert profile["status"] == 200
        assert profile["title"] == "Profile"

        session_dir = challenge / "artifacts" / "http" / "sessions" / "web"
        assert (session_dir / "session.json").is_file()
        assert (session_dir / "cookies.json").is_file()
        cookies = _json.loads((session_dir / "cookies.json").read_text(encoding="utf-8"))
        assert any(item["name"] == "session" and item["value"] == "sekret-cookie-value" for item in cookies)
        assert (session_dir / "requests.jsonl").is_file()
        records = [
            _json.loads(line)
            for line in (session_dir / "requests.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert len(records) == 2
        assert records[0]["method"] == "POST"
        assert records[1]["status"] == 200
        assert records[1]["request_body_file"] is None

        # Stored log metadata must not leak the cookie value.
        for log_path in (challenge / "logs").glob("*.json"):
            assert "sekret-cookie-value" not in log_path.read_text(encoding="utf-8")
        # Session record stores the request body for replay (local artifact).
        assert (session_dir / "req-000001.body").read_bytes() == b"user=admin&password=x"

        info = session_info(challenge, "web")
        assert info["request_count"] == 2
        assert "session" in info["cookies"]

        replay = replay_session(challenge, "web")
        assert replay["replayed"] == 2
        assert all(item["ok"] for item in replay["results"])
        assert replay["results"][-1]["status"] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_redirect_chain_is_recorded(tmp_path: Path):
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/next")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = b"<html><title>Next</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server, thread = _serve(RedirectHandler)
    try:
        port = server.server_address[1]
        challenge = init_challenge(tmp_path, "demo", "chain", "web", "AI_NATIVE", confirm_authorization=True)
        ScopeStore(challenge).add_host("127.0.0.1", [port])
        result = request(challenge, f"http://127.0.0.1:{port}/start", tag="start")
        assert result["status"] == 200
        assert result["title"] == "Next"
        assert len(result["redirect_chain"]) == 1
        assert result["redirect_chain"][0].endswith("/next")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
