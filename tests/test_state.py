import json
from pathlib import Path

import pytest

from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError, StateError
from ctf_agent.evidence import EvidenceLedger
from ctf_agent.runner import run_command
from ctf_agent.state import StateStore


def _log(challenge: Path, tag: str, text: str = "ok\n") -> str:
    """Create a real LOG-* fixture through the runner."""
    meta = run_command(challenge, ["printf", text], tag, "test", quiet=True, force=True)
    return meta["id"]


def test_state_and_evidence_updates(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "state", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    log1 = _log(challenge, "one")
    log2 = _log(challenge, "two")
    log3 = _log(challenge, "three")
    fact = store.add_fact("HTTP service exists", [log1], confidence="HIGH")
    hyp = store.add_hypothesis("Login is injectable", "Compare inputs", "Different response")
    store.update_hypothesis(hyp["id"], "REJECTED", "No difference")
    store.add_technique("admin:admin", "failed", [log2])
    store.set_next("Inspect upload endpoint", objective="Find file upload logic")

    # Legal progression: AUTHORIZED -> RECON -> HYPOTHESIS -> TESTING
    store.transition("RECON", "Initial recon complete", [log1])
    store.transition("HYPOTHESIS", "Testing login hypothesis", [log2])
    store.transition("TESTING", "Ready to test upload", [log3])

    state = store.load()
    assert state["facts"][0]["id"] == fact["id"]
    assert state["hypotheses"][0]["status"] == "REJECTED"
    assert state["techniques"]["failed"][0]["technique"] == "admin:admin"
    assert state["status"] == "TESTING"
    assert state["revision"] >= 3

    rendered = (challenge / "STATE.md").read_text(encoding="utf-8")
    assert "HTTP service exists" in rendered
    assert "No difference" in rendered
    assert f"Revision: `{state['revision']}`" in rendered

    evidence = EvidenceLedger(challenge).add(
        log1,
        "Port 80 open",
        "HTTP service likely exists",
        confidence="HIGH",
    )
    assert evidence["id"] == "E-000001"
    assert "Port 80 open" in (challenge / "EVIDENCE.md").read_text(encoding="utf-8")


def test_illegal_transition_is_rejected(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "illegal", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    log1 = _log(challenge, "one")
    with pytest.raises(StateError) as excinfo:
        store.transition("TESTING", "skip ahead", [log1])
    assert "Illegal state transition" in str(excinfo.value)
    assert "AUTHORIZED" in str(excinfo.value)

    store.transition("RECON", "recon complete", [log1])
    assert store.load()["status"] == "RECON"


def test_forced_transition_requires_evidence_and_is_audited(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "forced", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    with pytest.raises(StateError) as excinfo:
        store.transition("TESTING", "no evidence here", force=True)
    assert "require evidence" in str(excinfo.value).lower()

    log1 = _log(challenge, "one")
    store.transition("TESTING", "explicit override", [log1], force=True)
    state = store.load()
    assert state["status"] == "TESTING"
    events = [
        json.loads(line)
        for line in (challenge / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    transition_events = [item for item in events if item["type"] == "state_transition"]
    assert transition_events[-1]["payload"]["forced"] is True
    assert transition_events[-1]["payload"]["evidence"] == [log1]


def test_state_revision_detects_stale_save(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "stale", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    data = store.load()
    # A concurrent writer bumps the revision.
    StateStore(challenge).add_fact("Concurrent fact")
    with pytest.raises(StateError) as excinfo:
        store.save(data)
    assert "changed on disk" in str(excinfo.value)


def test_unresolved_evidence_references_are_rejected(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "evref", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    with pytest.raises(CTFError):
        store.add_fact("Fake log reference", ["LOG-999999"])

    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(CTFError):
        store.add_fact("Escaping artifact", [str(outside)])

    artifact = challenge / "work" / "note.txt"
    artifact.write_text("hello", encoding="utf-8")
    fact = store.add_fact("Inside artifact", ["work/note.txt"])
    assert fact["id"].startswith("F-")


def test_evidence_record_can_be_referenced(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "eref", "web", "AI_NATIVE", confirm_authorization=True)
    log1 = _log(challenge, "one")
    record = EvidenceLedger(challenge).add(log1, "Observation", "Meaning")
    fact = StateStore(challenge).add_fact("Backed by ledger record", [record["id"]])
    assert fact["evidence"] == [record["id"]]


def test_render_skips_rewrite_when_unchanged(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "renderskip", "web", "AI_NATIVE", confirm_authorization=True)
    store = StateStore(challenge)
    log1 = _log(challenge, "one")
    store.add_fact("Stable fact", [log1])
    state_md = challenge / "STATE.md"
    mtime = state_md.stat().st_mtime_ns
    store.render(store.load())  # identical content must not rewrite
    assert state_md.stat().st_mtime_ns == mtime

    ledger = EvidenceLedger(challenge)
    ledger.add(log1, "Observation", "Meaning")
    evidence_md = challenge / "EVIDENCE.md"
    emtime = evidence_md.stat().st_mtime_ns
    ledger.render()  # identical content must not rewrite
    assert evidence_md.stat().st_mtime_ns == emtime
