import shutil
from pathlib import Path

import pytest

from ctf_agent.adapters.elf import recon
from ctf_agent.challenge import init_challenge


@pytest.mark.skipif(shutil.which("checksec") is None, reason="checksec not installed")
def test_elf_adapter_extracts_structured_facts(tmp_path: Path):
    challenge = init_challenge(tmp_path, "demo", "elf", "pwn", "AI_NATIVE", confirm_authorization=True)
    result = recon(challenge, Path("/bin/true"))
    assert result["bits"] == 64
    assert result["arch"] == "amd64"
    assert result["endian"] == "little"
    assert result["relro"] == "full"
    assert result["nx"] is True
    assert result["pie"] is True
    assert result["sha256"]
    assert result["logs"]["checksec"].startswith("LOG-")
