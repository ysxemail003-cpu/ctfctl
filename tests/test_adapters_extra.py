"""Adapter error/branch coverage: recon, ghidra, elf."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf_agent.adapters import ghidra as ghidra_adapter
from ctf_agent.adapters import recon as recon_adapter
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError


def _challenge(tmp_path: Path, name: str = "adapter-extra") -> Path:
    return init_challenge(tmp_path, "demo", name, "misc", "AI_NATIVE", confirm_authorization=True)


def test_recon_on_elf_binary(tmp_path: Path):
    challenge = _challenge(tmp_path, "recon-bin")
    result = recon_adapter.file_recon(challenge, Path("/bin/true"))
    assert result["logs"]["file"].startswith("LOG-")
    assert result["size"] > 0
    assert "elf" in result  # ELF branch exercised
    assert result["elf"]["arch"] == "amd64"


def test_recon_rejects_missing_input(tmp_path: Path):
    challenge = _challenge(tmp_path, "recon-missing")
    with pytest.raises(CTFError):
        recon_adapter.file_recon(challenge, tmp_path / "missing.bin")


def test_ghidra_export_runs_or_reports_missing_tool(tmp_path: Path):
    challenge = _challenge(tmp_path, "ghidra-run")
    try:
        result = ghidra_adapter.export(challenge, Path("/bin/true"), force=False, timeout=60)
    except CTFError as exc:
        assert "analyzeHeadless" in str(exc)
    else:
        assert result.get("exit_code") == 0
        assert "function_count" in result
        assert result.get("function_count", 0) > 0


def test_elf_recon_missing_relative_and_non_elf(tmp_path: Path):
    import shutil

    from ctf_agent.adapters import elf as elf_adapter

    challenge = _challenge(tmp_path, "elf-extra")
    with pytest.raises(CTFError):
        elf_adapter.recon(challenge, tmp_path / "missing.bin")

    copied = challenge / "work" / "truecopy"
    shutil.copy2("/bin/true", copied)
    copied.chmod(0o755)
    relative = elf_adapter.recon(challenge, Path("work/truecopy"))
    assert relative["bits"] == 64
    assert relative["arch"] == "amd64"

    text_file = challenge / "work" / "notes.txt"
    text_file.write_text("hello not an elf", encoding="utf-8")
    result = elf_adapter.recon(challenge, text_file)
    assert result["logs"]["file"].startswith("LOG-")
    assert "bits" not in result  # no ELF classification
