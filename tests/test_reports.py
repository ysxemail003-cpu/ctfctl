import json
from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.report import final_report, handoff, merge_result


def test_handoff_merge_and_final_report(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "report", "web", "AI_NATIVE", confirm_authorization=True)
    handoff_path = handoff(
        challenge,
        "ctf-web",
        "Map HTTP surface",
        ["state.yaml"],
        ["Stay in scope"],
    )
    assert handoff_path.is_file()

    result_path = challenge / "reports" / "result-web.json"
    result_path.write_text(
        json.dumps(
            {
                "agent": "ctf-web",
                "status": "PARTIAL",
                "objective": "Map HTTP surface",
                "facts": [{"statement": "Root exists", "evidence": ["LOG-000001"]}],
                "hypotheses": [
                    {
                        "statement": "Login is vulnerable",
                        "test": "Compare inputs",
                        "expected": "Different response",
                    }
                ],
                "failed_techniques": ["admin:admin"],
                "recommended_next_action": "Diff login responses",
                "risk": "LOW",
            }
        ),
        encoding="utf-8",
    )
    merged = merge_result(challenge, result_path)
    assert merged["added"]["facts"] == ["F-0001"]
    assert merged["added"]["hypotheses"] == ["H-0001"]

    report = final_report(
        challenge,
        root_cause="Weak authentication",
        attack_path=["Recon", "Bypass"],
        exploit="scripts/solve.py",
        verification="Reproduced twice",
        lessons=["Validate identity server-side"],
    )
    assert report.is_file()
    assert "Weak authentication" in report.read_text(encoding="utf-8")
