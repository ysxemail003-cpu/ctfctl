"""Web adapter tests: ffuf fuzzing + read-only sqlmap automation."""
from __future__ import annotations

import http.server
import shutil
import socketserver
import threading
from pathlib import Path

import pytest

from ctf_agent.adapters import web as web_adapter
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError, ScopeError
from ctf_agent.runner import run_command


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    hits: set = set()

    def do_GET(self):  # noqa: N802
        if self.path in ("/admin", "/secret"):
            self.hits.add(self.path)
            body = b"hit"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):  # noqa: N802
        pass


@pytest.fixture()
def local_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _challenge(tmp_path: Path, name: str = "web", target: str | None = None, ports: list[int] | None = None) -> Path:
    return init_challenge(
        tmp_path, "demo", name, "web", "AI_NATIVE",
        target=target, ports=ports, confirm_authorization=True,
    )


def _wordlist(challenge: Path, words: list[str]) -> Path:
    path = challenge / "work" / "words.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


# --- sqlmap argv builder (pure, always runs) ---


def test_sqlmap_argv_is_conservative_and_capped():
    argv = web_adapter.build_sqlmap_argv("http://x/", level=9, risk=7)
    joined = " ".join(argv)
    assert "--batch" in argv
    assert "--crawl=0" in argv
    assert "--threads" in argv and "1" in argv
    assert "--level" in argv and "3" in argv  # capped
    assert "--risk" in argv and "2" in argv  # capped
    for dangerous in ("--os-shell", "--os-cmd", "--file-read", "--file-write", "--sql-shell", "--dbs"):
        assert dangerous not in joined


def test_sqlmap_argv_cleans_technique():
    argv = web_adapter.build_sqlmap_argv("http://x/", technique="B E U S T;--evil")
    joined = " ".join(argv)
    assert "--technique" in argv
    assert ";--evil" not in joined
    assert all(ch.isalpha() for ch in argv[argv.index("--technique") + 1])


# --- ffuf validation errors ---


def test_ffuf_requires_fuzz_keyword(tmp_path: Path):
    challenge = _challenge(tmp_path)
    words = _wordlist(challenge, ["admin"])
    with pytest.raises(CTFError):
        web_adapter.ffuf_scan(challenge, "http://127.0.0.1:1/", str(words))


def test_ffuf_rejects_bad_match_codes_and_rate(tmp_path: Path):
    challenge = _challenge(tmp_path)
    words = _wordlist(challenge, ["admin"])
    with pytest.raises(CTFError):
        web_adapter.ffuf_scan(challenge, "http://127.0.0.1:1/FUZZ", str(words), match_codes="200; rm -rf /")
    with pytest.raises(CTFError):
        web_adapter.ffuf_scan(challenge, "http://127.0.0.1:1/FUZZ", str(words), rate=99999)


def test_ffuf_rejects_missing_wordlist(tmp_path: Path):
    challenge = _challenge(tmp_path)
    with pytest.raises(CTFError):
        web_adapter.ffuf_scan(challenge, "http://127.0.0.1:1/FUZZ", str(challenge / "work" / "nope.txt"))


def test_ffuf_refuses_out_of_scope_host(tmp_path: Path):
    challenge = _challenge(tmp_path)
    words = _wordlist(challenge, ["admin"])
    with pytest.raises(ScopeError):
        web_adapter.ffuf_scan(challenge, "http://127.0.0.1:1/FUZZ", str(words))


# --- ffuf end-to-end against a local server ---


@pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf not installed")
def test_ffuf_discovers_local_paths(tmp_path: Path, local_server):
    port = local_server.server_address[1]
    challenge = _challenge(tmp_path, "web-ffuf", target="127.0.0.1", ports=[port])
    words = _wordlist(challenge, ["admin", "secret", "missing"])
    result = web_adapter.ffuf_scan(challenge, f"http://127.0.0.1:{port}/FUZZ", str(words))
    found = {hit["word"] for hit in result["hits"]}
    assert "admin" in found
    assert "secret" in found
    assert "missing" not in found
    assert result["requests_budgeted"] == 3
    assert result["logs"]["ffuf"].startswith("LOG-")
    assert (challenge / result["artifacts"]["json"]).is_file()


# --- sqlmap evidence gate + execution summary ---


@pytest.mark.skipif(shutil.which("sqlmap") is None, reason="sqlmap not installed")
def test_sqlmap_requires_evidence(tmp_path: Path):
    challenge = _challenge(tmp_path)
    with pytest.raises(CTFError):
        web_adapter.sqlmap_audit(challenge, "http://127.0.0.1:1/x")


@pytest.mark.skipif(shutil.which("sqlmap") is None, reason="sqlmap not installed")
def test_sqlmap_rejects_unresolved_evidence(tmp_path: Path):
    challenge = _challenge(tmp_path)
    with pytest.raises(CTFError):
        web_adapter.sqlmap_audit(challenge, "http://127.0.0.1:1/x", evidence_ref="LOG-999999")


def test_sqlmap_success_with_real_evidence_and_stubbed_runner(tmp_path: Path, monkeypatch):
    challenge = _challenge(tmp_path, "web-sqlmap", target="127.0.0.1", ports=[80])
    log = run_command(challenge, ["printf", "manual probe"], "probe", quiet=True)
    fake_stdout = challenge / "logs" / "fake-sqlmap.stdout"
    fake_stdout.write_text(
        "[INFO] testing connection to the target URL\n"
        "[INFO] GET parameter 'id' is vulnerable\n"
        "[INFO] back-end DBMS: MySQL\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        web_adapter,
        "run_command",
        lambda *a, **k: {"id": "LOG-000099", "stdout_file": "logs/fake-sqlmap.stdout"},
    )
    result = web_adapter.sqlmap_audit(challenge, "http://127.0.0.1:80/x?id=1", evidence_ref=log["id"])
    assert result["detected_vulnerable"] is True
    assert any("vulnerable" in line for line in result["excerpt"])
    assert result["logs"]["sqlmap"] == "LOG-000099"


def test_sqlmap_force_with_stubbed_runner(tmp_path: Path, monkeypatch):
    challenge = _challenge(tmp_path, "web-sqlmap-force", target="127.0.0.1", ports=[80])
    fake_stdout = challenge / "logs" / "fake-sqlmap2.stdout"
    fake_stdout.write_text("[INFO] URI parameter 'q' is not injectable\n", encoding="utf-8")
    monkeypatch.setattr(
        web_adapter,
        "run_command",
        lambda *a, **k: {"id": "LOG-000100", "stdout_file": "logs/fake-sqlmap2.stdout"},
    )
    result = web_adapter.sqlmap_audit(challenge, "http://127.0.0.1:80/?q=x", force=True)
    assert result["detected_vulnerable"] is False
    assert result["tool"] == "sqlmap"
