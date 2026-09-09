"""Runtime enforcement of .scope.yaml limits (requests, rate, ports, runtime)."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError, ScopeError
from ctf_agent.policy import PolicyError
from ctf_agent.scope import ScopeStore


def _challenge(tmp_path: Path, name: str, **scope_overrides) -> Path:
    challenge = init_challenge(tmp_path, "demo", name, "web", "AI_NATIVE", confirm_authorization=True)
    store = ScopeStore(challenge)
    data = store.load()
    limits = data.setdefault("limits", {})
    limits.update(scope_overrides.get("limits", {}))
    if "usage" in scope_overrides:
        usage = data.setdefault("usage", {})
        usage.update(scope_overrides["usage"])
    store.save(data)
    return challenge


def test_max_requests_is_enforced_by_http_adapter(tmp_path: Path):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from ctf_agent.adapters.http import request

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"ok"
            self.send_response(200)
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
        challenge = _challenge(tmp_path, "maxreq", limits={"max_requests": 2, "request_rate_per_second": 0})
        ScopeStore(challenge).add_host("127.0.0.1", [port])
        url = f"http://127.0.0.1:{port}/"
        assert request(challenge, url, tag="one")["status"] == 200
        assert request(challenge, url, tag="two")["status"] == 200
        with pytest.raises((PolicyError, CTFError)):
            request(challenge, url, tag="three")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_request_rate_limit(tmp_path: Path):
    challenge = _challenge(
        tmp_path,
        "rate",
        limits={"request_rate_per_second": 1000},
    )
    store = ScopeStore(challenge)
    data = store.load()
    data["usage"]["last_request_at"] = time.time() + 1  # in the future -> always inside the window
    store.save(data)
    with pytest.raises(ScopeError) as excinfo:
        store.commit_usage({"requests": 1})
    assert "rate limit" in str(excinfo.value).lower()
    # After the window elapses the request is accepted.
    time.sleep(0.01)
    data = store.load()
    data["usage"]["last_request_at"] = time.time() - 10
    store.save(data)
    store.commit_usage({"requests": 1})


def test_scan_port_budget_is_enforced(tmp_path: Path):
    challenge = _challenge(tmp_path, "ports", limits={"max_scan_ports": 100})
    store = ScopeStore(challenge)
    with pytest.raises(PolicyError) as excinfo:
        store.commit_usage({"scan_ports": 101})
    assert "max_scan_ports" in str(excinfo.value)


def test_runtime_budget_blocks_new_commands(tmp_path: Path):
    from ctf_agent.runner import run_command

    challenge = _challenge(tmp_path, "runtime", usage={"runtime_seconds": 999999})
    with pytest.raises(CTFError) as excinfo:
        run_command(challenge, ["printf", "hi\n"], "blocked", "test", quiet=True)
    assert "budget" in str(excinfo.value).lower()


def test_runtime_usage_is_committed_after_run(tmp_path: Path):
    from ctf_agent.runner import run_command

    challenge = _challenge(tmp_path, "runtime-commit")
    store = ScopeStore(challenge)
    before = store.usage()["runtime_seconds"]
    run_command(challenge, ["printf", "hi\n"], "commit", "test", quiet=True)
    after = store.usage()["runtime_seconds"]
    assert after >= before + 1
