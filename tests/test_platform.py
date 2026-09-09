"""CTFd platform bridge tests against a local mock server."""
from __future__ import annotations

import http.server
import json
import socketserver
import threading
import zipfile

import pytest

from ctf_agent.cli import main
from ctf_agent.errors import CTFError
from ctf_agent.platform import CTFdPlatform

TOKEN = "mock-token-123"


class _MockCTFdHandler(http.server.BaseHTTPRequestHandler):
    challenges = [
        {"id": 1, "name": "Mock Web", "category": "web", "value": 100, "type": "standard"},
        {"id": 2, "name": "Mock Pwn", "category": "pwn", "value": 200, "type": "standard"},
    ]
    zip_bytes = None

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == TOKEN

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if not self._authorized():
            self._json({"success": False, "message": "unauthorized"}, status=401)
            return
        if self.path == "/api/v1/challenges":
            self._json({"success": True, "data": self.challenges})
            return
        if self.path.startswith("/api/v1/challenges/"):
            challenge_id = int(self.path.rsplit("/", 1)[-1])
            for item in self.challenges:
                if item["id"] == challenge_id:
                    data = dict(item)
                    data["description"] = f"Solve {item['name']}"
                    data["files"] = [f"/files/{challenge_id}.zip"]
                    self._json({"success": True, "data": data})
                    return
            self._json({"success": False, "message": "not found"}, status=404)
            return
        if self.path.startswith("/files/") and self.zip_bytes is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.zip_bytes)))
            self.end_headers()
            self.wfile.write(self.zip_bytes)
            return
        self._json({"success": False, "message": "not found"}, status=404)

    def do_POST(self):  # noqa: N802
        if not self._authorized():
            self._json({"success": False, "message": "unauthorized"}, status=401)
            return
        if self.path == "/api/v1/challenges/attempt":
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length).decode())
            if payload.get("challenge_id") == 1 and payload.get("submission") == "flag{correct}":
                self._json({"success": True, "data": {"status": "correct", "message": "Correct"}})
                return
            self._json({"success": True, "data": {"status": "incorrect", "message": "Incorrect"}})
            return
        self._json({"success": False, "message": "not found"}, status=404)

    def log_message(self, *args):  # noqa: N802
        pass


@pytest.fixture()
def mock_ctfd():
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("challenge.txt", "solve me")
    _MockCTFdHandler.zip_bytes = buffer.getvalue()
    server = socketserver.TCPServer(("127.0.0.1", 0), _MockCTFdHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _platform(url: str, token_env: str = "CTFD_TEST") -> CTFdPlatform:
    return CTFdPlatform(url, token_env=token_env)


def test_platform_requires_token_env(mock_ctfd, monkeypatch):
    monkeypatch.delenv("CTFD_TEST", raising=False)
    with pytest.raises(CTFError, match="token not found"):
        _platform(mock_ctfd)


def test_platform_list(mock_ctfd, monkeypatch):
    monkeypatch.setenv("CTFD_TEST", TOKEN)
    challenges = _platform(mock_ctfd).list_challenges()
    assert [c.id for c in challenges] == [1, 2]
    assert challenges[0].category == "web"


def test_platform_detail_and_download(mock_ctfd, tmp_path, monkeypatch):
    monkeypatch.setenv("CTFD_TEST", TOKEN)
    platform = _platform(mock_ctfd)
    detail = platform.challenge_detail(1)
    assert detail.description == "Solve Mock Web"
    assert detail.files == ["/files/1.zip"]
    downloaded = platform.download_file(detail.files[0], tmp_path)
    assert downloaded.is_file()
    with zipfile.ZipFile(downloaded) as zf:
        assert zf.read("challenge.txt") == b"solve me"


def test_platform_download_refuses_cross_host(mock_ctfd, tmp_path, monkeypatch):
    monkeypatch.setenv("CTFD_TEST", TOKEN)
    platform = _platform(mock_ctfd)
    with pytest.raises(CTFError, match="outside the CTFd host"):
        platform.download_file("http://evil.example/flag.zip", tmp_path)


def test_platform_submit_flag(mock_ctfd, monkeypatch):
    monkeypatch.setenv("CTFD_TEST", TOKEN)
    platform = _platform(mock_ctfd)
    assert platform.submit_flag(1, "flag{correct}")["status"] == "correct"
    assert platform.submit_flag(1, "flag{wrong}")["status"] == "incorrect"


def test_platform_pull_creates_workspace(mock_ctfd, tmp_path, monkeypatch):
    monkeypatch.setenv("CTFD_TEST", TOKEN)
    workspace = tmp_path / "ws"
    rc = main(
        [
            "platform", "ctfd", "pull",
            "--url", mock_ctfd,
            "--event", "demo-ctf",
            "--token-env", "CTFD_TEST",
            "--workspace", str(workspace),
        ]
    )
    assert rc == 0
    web_dir = workspace / "contests" / "demo-ctf" / "mock-web"
    pwn_dir = workspace / "contests" / "demo-ctf" / "mock-pwn"
    assert (web_dir / "state.yaml").is_file()
    assert (pwn_dir / "state.yaml").is_file()
    assert (web_dir / "original" / "1.zip").is_file()
    import yaml

    state = yaml.safe_load((web_dir / "state.yaml").read_text())
    assert "no_auto_submit" in state.get("operator_constraints", [])

    # second pull is idempotent
    rc2 = main(
        [
            "platform", "ctfd", "pull",
            "--url", mock_ctfd,
            "--event", "demo-ctf",
            "--token-env", "CTFD_TEST",
            "--workspace", str(workspace),
        ]
    )
    assert rc2 == 0
