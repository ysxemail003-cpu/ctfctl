from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.evidence import EvidenceLedger
from ctf_agent.state import StateStore


def test_state_and_evidence_updates(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "state", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    fact = store.add_fact("HTTP service exists", ["LOG-000001"], confidence="HIGH")
    hyp = store.add_hypothesis("Login is injectable", "Compare inputs", "Different response")
    store.update_hypothesis(hyp["id"], "REJECTED", "No difference")
    store.add_technique("admin:admin", "failed", ["LOG-000002"])
    store.set_next("Inspect upload endpoint", objective="Find file upload logic")
    store.transition("TESTING", "Ready to test upload", ["LOG-000003"])

    state = store.load()
    assert state["facts"][0]["id"] == fact["id"]
    assert state["hypotheses"][0]["status"] == "REJECTED"
    assert state["techniques"]["failed"][0]["technique"] == "admin:admin"
    assert state["status"] == "TESTING"

    rendered = (challenge / "STATE.md").read_text(encoding="utf-8")
    assert "HTTP service exists" in rendered
    assert "No difference" in rendered

    evidence = EvidenceLedger(challenge).add(
        "LOG-000001",
        "Port 80 open",
        "HTTP service likely exists",
        confidence="HIGH",
    )
    assert evidence["id"] == "E-000001"
    assert "Port 80 open" in (challenge / "EVIDENCE.md").read_text(encoding="utf-8")
