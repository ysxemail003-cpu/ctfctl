"""Evidence-safe log archival: referenced logs stay, orphans move."""
from __future__ import annotations

from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.logarchive import archive_logs, plan_archive, summary
from ctf_agent.runner import run_command
from ctf_agent.state import StateStore


def _challenge(tmp_path: Path, name: str = "logarch") -> Path:
    return init_challenge(tmp_path, "demo", name, "misc", "AI_NATIVE", confirm_authorization=True)


def test_summary_counts_logs(tmp_path: Path):
    challenge = _challenge(tmp_path)
    run_command(challenge, ["printf", "a\n"], "alpha", "recon", quiet=True)
    run_command(challenge, ["printf", "b\n"], "beta", "recon", quiet=True)
    info = summary(challenge)
    assert info["log_count"] == 2
    assert info["by_tag"]["alpha"] == 1
    assert info["referenced_count"] == 0


def test_archive_moves_only_unreferenced_logs(tmp_path: Path):
    challenge = _challenge(tmp_path)
    referenced = run_command(challenge, ["printf", "keep\n"], "keep", "recon", quiet=True)["id"]
    orphan = run_command(challenge, ["printf", "drop\n"], "drop", "recon", quiet=True)["id"]
    StateStore(challenge).add_fact("Keep this", [referenced])

    plan = plan_archive(challenge)
    assert plan["candidate_count"] == 1
    assert plan["candidates"][0]["id"] == orphan
    assert referenced not in [item["id"] for item in plan["candidates"]]

    preview = archive_logs(challenge, dry_run=True)
    assert preview["dry_run"] is True
    # Nothing moved in dry-run mode.
    assert (challenge / preview["candidates"][0]["metadata"]).is_file()

    result = archive_logs(challenge, dry_run=False)
    assert result["moved_count"] == 1
    # Referenced metadata still in place and resolvable.
    assert (challenge / "logs" / f"{referenced.split('-')[1]}-keep.json").is_file()
    # Orphan is gone from the active logs root and present under archive/.
    from ctf_agent.logindex import metadata_files

    active = [path.name for path in metadata_files(challenge / "logs")]
    assert f"{orphan.split('-')[1]}-drop.json" not in active
    archived = list((challenge / "logs" / "archive").rglob("*.json"))
    assert len(archived) == 1
    assert archived[0].name == f"{orphan.split('-')[1]}-drop.json"
