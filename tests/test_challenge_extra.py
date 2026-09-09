"""Challenge selector/pointer edge cases."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf_agent.challenge import (
    find_challenge_dir,
    get_current_challenge,
    list_challenges,
    resolve_challenge_selector,
    set_current_challenge,
)
from ctf_agent.errors import CTFError
from ctf_agent.util import atomic_write_text


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "ws"
    (workspace / "contests").mkdir(parents=True)
    return workspace


def test_init_duplicate_and_list_skips_invalid(tmp_path: Path):
    from ctf_agent.challenge import init_challenge

    workspace = _workspace(tmp_path)
    path = init_challenge(workspace, "demo", "dup", "web", "AI_NATIVE", confirm_authorization=True)
    with pytest.raises(CTFError):
        init_challenge(workspace, "demo", "dup", "web", "AI_NATIVE")

    # sibling without state.yaml, and one with corrupt state.yaml
    (path.parent / "no-state").mkdir()
    corrupt = path.parent / "corrupt"
    corrupt.mkdir()
    (corrupt / "state.yaml").write_text("{ not yaml", encoding="utf-8")

    items = list_challenges(workspace)
    names = [item["challenge"] for item in items]
    assert names == ["dup"]


def test_resolve_selector_ambiguous_and_missing(tmp_path: Path):
    from ctf_agent.challenge import init_challenge

    workspace = _workspace(tmp_path)
    init_challenge(workspace, "event-a", "alpha", "web", "AI_NATIVE", confirm_authorization=True)
    init_challenge(workspace, "event-b", "alpha", "web", "AI_NATIVE", confirm_authorization=True)
    with pytest.raises(CTFError) as excinfo:
        resolve_challenge_selector(workspace, "alpha")
    assert "ambiguous" in str(excinfo.value).lower()
    with pytest.raises(CTFError):
        resolve_challenge_selector(workspace, "nope/nope")
    # event/challenge form resolves
    assert resolve_challenge_selector(workspace, "event-a/alpha").name == "alpha"


def test_current_pointer_roundtrip_and_bad_pointer(tmp_path: Path):
    from ctf_agent.challenge import init_challenge

    workspace = _workspace(tmp_path)
    path = init_challenge(workspace, "demo", "ptr", "web", "AI_NATIVE", confirm_authorization=True)
    assert get_current_challenge(workspace) is None
    record = set_current_challenge(workspace, path)
    assert record["challenge"] == "ptr"
    assert get_current_challenge(workspace) == path.resolve()

    # pointer to a missing challenge resolves to None
    atomic_write_text(workspace / "current.yaml", "path: /does/not/exist\nschema_version: 1\n")
    assert get_current_challenge(workspace) is None


def test_find_challenge_dir_modes(tmp_path: Path, monkeypatch):
    from ctf_agent.challenge import init_challenge

    workspace = _workspace(tmp_path)
    path = init_challenge(workspace, "demo", "find", "web", "AI_NATIVE", confirm_authorization=True)
    assert find_challenge_dir(str(path)) == path.resolve()
    with pytest.raises(CTFError):
        find_challenge_dir(str(tmp_path / "not-a-challenge"))

    monkeypatch.setenv("CTF_CHALLENGE_DIR", str(path))
    assert find_challenge_dir() == path.resolve()
    monkeypatch.setenv("CTF_CHALLENGE_DIR", "/no/such/dir")
    with pytest.raises(CTFError):
        find_challenge_dir()

    monkeypatch.delenv("CTF_CHALLENGE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)  # cwd must not resolve to a challenge
    monkeypatch.setattr(
        "ctf_agent.challenge.get_current_challenge", lambda workspace: None
    )
    with pytest.raises(CTFError):
        find_challenge_dir()  # no env, cwd, or durable pointer
