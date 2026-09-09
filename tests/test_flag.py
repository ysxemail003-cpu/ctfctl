from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.flag import candidate, detect, verify_replay
from ctf_agent.state import StateStore


def test_flag_reproduction_requires_matching_runs(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "flag", "misc", "AI_NATIVE", confirm_authorization=True)
    candidate(challenge, "flag{stable}", "manual", "echo flag{stable}")
    result = verify_replay(challenge, "printf 'flag{stable}\\n'", runs=2)
    assert result["verified"] is True
    assert result["value"] == "flag{stable}"

    state = StateStore(challenge).load()
    assert state["flag"]["status"] == "REPRODUCED"
    assert state["flag"]["reproduction"]["runs"] == 2
    assert state["flag"]["reproduction"]["values_match"] is True
    assert state["status"] == "VERIFICATION"
    assert "submit" in state["next_action"].lower()

    matches = detect(challenge)
    assert any(item["value"] == "flag{stable}" for item in matches)


def test_flag_submission_acceptance_updates_state(tmp_path: Path, monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from ctf_agent.flag import submit
    from ctf_agent.scope import ScopeStore

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = b'{"success":true,"data":{"status":"correct"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("CTFD_TOKEN", "test-token")
    try:
        challenge = init_challenge(tmp_path, "demo", "submit", "misc", "AI_NATIVE", confirm_authorization=True)
        ScopeStore(challenge).add_host("127.0.0.1", [server.server_address[1]])
        ScopeStore(challenge).allow("flag-submission")
        candidate(challenge, "flag{accepted}", "manual")
        verify_replay(challenge, "printf 'flag{accepted}\\n'", runs=2)
        result = submit(
            challenge,
            f"http://127.0.0.1:{server.server_address[1]}/api/v1/flags",
            "CTFD_TOKEN",
            1,
            yes=True,
        )
        assert result["accepted"] is True
        state = StateStore(challenge).load()
        assert state["flag"]["status"] == "ACCEPTED"
        assert state["flag"]["submission"]["accepted"] is True
        assert state["status"] == "SOLVED"
        assert (challenge / "flags" / "accepted.txt").is_file()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_no_auto_submit_constraint_blocks_submission(tmp_path: Path):
    from ctf_agent.errors import FlagError
    from ctf_agent.flag import candidate, submit
    from ctf_agent.scope import ScopeStore
    from ctf_agent.state import StateStore

    challenge = init_challenge(
        tmp_path,
        "demo",
        "constraint",
        "misc",
        "AI_NATIVE",
        confirm_authorization=True,
        constraints=["no_auto_submit"],
    )
    ScopeStore(challenge).allow("flag-submission")
    candidate(challenge, "flag{blocked}", "manual")
    try:
        submit(challenge, "http://127.0.0.1:1/api", "CTFD_TOKEN", 1, yes=True)
    except FlagError as exc:
        assert "no_auto_submit" in str(exc)
    else:
        raise AssertionError("expected no_auto_submit constraint to block submission")

    StateStore(challenge).remove_constraint("no_auto_submit")
    assert StateStore(challenge).load()["operator_constraints"] == []


def test_submission_requires_reproduced_flag(tmp_path: Path):
    from ctf_agent.errors import FlagError
    from ctf_agent.flag import candidate, submit
    from ctf_agent.scope import ScopeStore

    challenge = init_challenge(tmp_path, "demo", "unreproduced", "misc", "AI_NATIVE", confirm_authorization=True)
    ScopeStore(challenge).add_host("127.0.0.1", [1])
    ScopeStore(challenge).allow("flag-submission")
    candidate(challenge, "flag{not-reproduced}", "manual")
    try:
        submit(challenge, "http://127.0.0.1:1/api", "CTFD_TOKEN", 1, yes=True)
    except FlagError as exc:
        assert "reproduced" in str(exc)
    else:
        raise AssertionError("expected reproduction requirement")
