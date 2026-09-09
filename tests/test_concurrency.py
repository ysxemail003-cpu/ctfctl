"""Multi-process concurrency regressions for state, evidence, and merge.

These tests spawn real processes (fork) that share one challenge directory and
rely on the challenge runtime lock for atomic ID allocation and mutations.
"""
from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.runner import run_command
from ctf_agent.state import StateStore


def _spawn_workers(count: int, target, challenge: Path, queue) -> list:
    ctx = multiprocessing.get_context("fork")
    procs = [
        ctx.Process(target=target, args=(str(challenge), queue))
        for _ in range(count)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(120)
    assert all(proc.exitcode == 0 for proc in procs), "a concurrent worker failed"
    return procs


def _add_facts_worker(challenge: str, queue) -> None:
    from ctf_agent.state import StateStore

    store = StateStore(Path(challenge))
    for index in range(5):
        record = store.add_fact(f"concurrent fact {index}")
        queue.put(record["id"])


def _add_evidence_worker(challenge: str, queue) -> None:
    from ctf_agent.evidence import EvidenceLedger

    ledger = EvidenceLedger(Path(challenge))
    for index in range(4):
        record = ledger.add("concurrency-test", f"observation {index}", "meaning")
        queue.put(record["id"])


def _merge_worker(challenge: str, queue) -> None:
    from ctf_agent.report import merge_result

    challenge_dir = Path(challenge)
    result_path = challenge_dir / "reports" / "result-web.json"
    try:
        result = merge_result(challenge_dir, result_path)
        queue.put(("merged", result.get("merged"), result.get("reason")))
    except Exception as exc:  # pragma: no cover - unexpected path
        queue.put(("error", str(exc), None))


def test_concurrent_state_updates_do_not_lose_facts(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "state-conc", "web", "AI_NATIVE", confirm_authorization=True)
    queue: multiprocessing.queues.Queue = multiprocessing.get_context("fork").Queue()
    _spawn_workers(4, _add_facts_worker, challenge, queue)

    ids = [queue.get(timeout=10) for _ in range(20)]
    assert len(set(ids)) == 20, "duplicate F-* ids under concurrency"

    state = StateStore(challenge).load()
    assert len(state["facts"]) == 20
    assert len({fact["id"] for fact in state["facts"]}) == 20
    assert state["revision"] == 21  # init=1 + 20 fact revisions

    # events.jsonl must remain valid JSON lines with unique EVT ids
    event_lines = (challenge / "events.jsonl").read_text(encoding="utf-8").splitlines()
    parsed = [json.loads(line) for line in event_lines]
    event_ids = [item["id"] for item in parsed]
    assert len(event_ids) == len(set(event_ids))


def test_concurrent_evidence_appends_are_unique(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "ev-conc", "web", "AI_NATIVE", confirm_authorization=True)
    queue: multiprocessing.queues.Queue = multiprocessing.get_context("fork").Queue()
    _spawn_workers(4, _add_evidence_worker, challenge, queue)

    ids = [queue.get(timeout=10) for _ in range(16)]
    assert len(set(ids)) == 16, "duplicate E-* ids under concurrency"

    from ctf_agent.evidence import EvidenceLedger

    records = EvidenceLedger(challenge).records()
    assert len(records) == 16
    assert len({record["id"] for record in records}) == 16


def test_concurrent_duplicate_merge_is_idempotent(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "merge-conc", "web", "AI_NATIVE", confirm_authorization=True)
    log_id = run_command(challenge, ["printf", "ok\n"], "root", "test", quiet=True, force=True)["id"]
    result_path = challenge / "reports" / "result-web.json"
    result_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "agent": "ctf-agent-web",
                "status": "PARTIAL",
                "facts": [{"statement": "Root exists", "evidence": [log_id]}],
                "hypotheses": [],
                "failed_techniques": [],
                "recommended_next_action": "Diff login responses",
            }
        ),
        encoding="utf-8",
    )

    queue: multiprocessing.queues.Queue = multiprocessing.get_context("fork").Queue()
    _spawn_workers(4, _merge_worker, challenge, queue)

    outcomes = [queue.get(timeout=10) for _ in range(4)]
    merged_count = sum(1 for kind, merged, _reason in outcomes if kind == "merged" and merged is True)
    already_count = sum(1 for kind, _m, reason in outcomes if kind == "merged" and reason == "already_merged")
    assert merged_count == 1, outcomes
    assert already_count == 3, outcomes

    state = StateStore(challenge).load()
    assert len(state["facts"]) == 1
    history = (challenge / "reports" / "merged-results.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(history) == 1
