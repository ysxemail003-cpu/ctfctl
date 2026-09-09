from pathlib import Path

from ctf_agent.challenge import init_challenge
from ctf_agent.scope import ScopeStore
from ctf_agent.state import StateStore


def test_init_creates_auditable_challenge(tmp_path: Path):
    path = init_challenge(
        tmp_path,
        event="Demo Event",
        challenge="Web Login",
        category="web",
        mode="AI_NATIVE",
        target="example.ctf",
        ports=[80, 443],
        confirm_authorization=True,
    )
    assert (path / "state.yaml").is_file()
    assert (path / "STATE.md").is_file()
    assert (path / "EVIDENCE.md").is_file()
    assert (path / ".scope.yaml").is_file()
    assert (path / "logs").is_dir()
    assert (path / "original").is_dir()

    state = StateStore(path).load()
    assert state["challenge"]["name"] == "web-login"
    assert state["status"] == "AUTHORIZED"
    assert state["authorization"]["confirmed"] is True

    scope = ScopeStore(path)
    assert scope.check("http://example.ctf/")["allowed"] is True
    assert scope.check("example.ctf", 80)["allowed"] is True

    url_path = init_challenge(tmp_path / "url", "demo", "url", "web", "AI_NATIVE", target="http://example.ctf/", confirm_authorization=True)
    assert ScopeStore(url_path).check("http://example.ctf/")["allowed"] is True


def test_scope_rejects_outside_host(tmp_path: Path):
    path = init_challenge(tmp_path, "demo", "pwn", "pwn", "AI_NATIVE", confirm_authorization=True)
    scope = ScopeStore(path)
    scope.add_host("allowed.example", [1337])
    try:
        scope.check("other.example", 80)
    except Exception as exc:
        assert "outside authorized scope" in str(exc)
    else:
        raise AssertionError("expected scope rejection")


def test_ai_assisted_blocks_network_until_automation_allowed(tmp_path: Path):
    from ctf_agent.challenge import init_challenge
    from ctf_agent.scope import ScopeStore

    challenge = init_challenge(
        tmp_path,
        "demo",
        "assisted",
        "web",
        "AI_ASSISTED",
        target="example.ctf",
        ports=[80],
        confirm_authorization=True,
    )
    scope = ScopeStore(challenge)
    try:
        scope.check("http://example.ctf/")
    except Exception as exc:
        assert "AI_ASSISTED" in str(exc)
    else:
        raise AssertionError("expected AI_ASSISTED network automation block")

    data = scope.load()
    data["authorization"]["rules"]["allow_automation"] = True
    scope.save(data)
    assert scope.check("http://example.ctf/")["allowed"] is True
