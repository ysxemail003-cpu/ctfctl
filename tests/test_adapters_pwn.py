"""Pwn/rev helper adapter tests: ROP gadgets and dynamic imports."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ctf_agent.adapters import pwn as pwn_adapter
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError


def _challenge(tmp_path: Path, name: str = "pwn") -> Path:
    return init_challenge(tmp_path, "demo", name, "pwn", "AI_NATIVE", confirm_authorization=True)


def test_rop_rejects_missing_binary(tmp_path: Path):
    challenge = _challenge(tmp_path)
    with pytest.raises(CTFError):
        pwn_adapter.rop_gadgets(challenge, tmp_path / "missing.bin")


def test_imports_rejects_missing_binary(tmp_path: Path):
    challenge = _challenge(tmp_path)
    with pytest.raises(CTFError):
        pwn_adapter.dyn_imports(challenge, tmp_path / "missing.bin")


@pytest.mark.skipif(shutil.which("ROPgadget") is None, reason="ROPgadget not installed")
def test_rop_gadgets_structured(tmp_path: Path):
    challenge = _challenge(tmp_path, "pwn-rop")
    result = pwn_adapter.rop_gadgets(challenge, Path("/bin/true"), only="pop|ret", max_gadgets=50)
    assert result["gadget_count"] > 0
    assert result["gadget_count"] <= 50
    first = result["gadgets"][0]
    assert isinstance(first["address"], int)
    assert "ret" in first["gadget"].lower()
    assert result["logs"]["ropgadget"].startswith("LOG-")


@pytest.mark.skipif(shutil.which("readelf") is None, reason="readelf not installed")
def test_dyn_imports_structured(tmp_path: Path):
    challenge = _challenge(tmp_path, "pwn-imports")
    result = pwn_adapter.dyn_imports(challenge, Path("/bin/true"))
    assert result["import_count"] > 0
    names = {item["name"] for item in result["imports"]}
    assert len(names) == result["import_count"]
    assert any(name in names for name in ("getenv", "abort", "free", "__libc_start_main"))
    assert result["logs"]["readelf"].startswith("LOG-")
