"""CLI integration for the Phase A1/A2 tool adapters (crypto + forensics).

Exercising through ``ctfctl`` main() also covers the dispatch layer
(commands/tool_cmd.py) that the module-level tests do not reach.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ctf_agent.cli import main
from ctf_fixtures import MD5_PASSWORD, pcap_bytes, png_bytes, zip_bytes


def _init(tmp_path: Path, name: str) -> Path:
    workspace = tmp_path / "ws"
    rc = main(
        [
            "init",
            "--workspace",
            str(workspace),
            "--event",
            "demo",
            "--challenge",
            name,
            "--category",
            "crypto",
            "--mode",
            "AI_NATIVE",
            "--confirm-authorization",
            "--no-current",
        ]
    )
    assert rc == 0
    return workspace / "contests" / "demo" / name


def _run_json(challenge: Path, capsys, *args) -> dict:
    capsys.readouterr()  # discard init/previous output
    rc = main(["-C", str(challenge), *args])
    assert rc == 0, f"CLI failed: {args}"
    return json.loads(capsys.readouterr().out)


def _write(challenge: Path, name: str, data: bytes) -> Path:
    path = challenge / "work" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.mark.skipif(shutil.which("hashid") is None, reason="hashid not installed")
def test_cli_hashid(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-hashid")
    result = _run_json(challenge, capsys, "tool", "hashid", MD5_PASSWORD)
    assert result["shape"]["family"] == "md5-hex"
    assert any("md5" in c["name"].lower() for c in result["candidates"])


@pytest.mark.skipif(shutil.which("john") is None, reason="john not installed")
def test_cli_crack_john(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-crack")
    words = challenge / "work" / "words.txt"
    words.parent.mkdir(parents=True, exist_ok=True)
    words.write_text("password\n", encoding="utf-8")
    result = _run_json(
        challenge, capsys, "tool", "crack", MD5_PASSWORD, "--wordlist", str(words), "--tool", "john"
    )
    assert result["status"] == "cracked"
    assert "password" in result["plaintexts"]


@pytest.mark.skipif(shutil.which("exiftool") is None, reason="exiftool not installed")
def test_cli_exif(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-exif")
    source = _write(challenge, "pic.png", png_bytes())
    result = _run_json(challenge, capsys, "tool", "exif", str(source))
    assert result["tags"].get("FileType") == "PNG"


@pytest.mark.skipif(shutil.which("binwalk") is None, reason="binwalk not installed")
def test_cli_binwalk_scan_and_extract(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-binwalk")
    source = _write(challenge, "carrier.png", png_bytes() + zip_bytes())
    result = _run_json(challenge, capsys, "tool", "binwalk", str(source))
    assert any("Zip archive" in e["description"] for e in result["entries"])
    extracted = _run_json(challenge, capsys, "tool", "binwalk", str(source), "--extract")
    assert extracted["extracted"] is not None
    assert extracted["extracted"]["file_count"] >= 1


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")
def test_cli_archive(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-archive")
    source = _write(challenge, "arch.zip", zip_bytes())
    result = _run_json(challenge, capsys, "tool", "archive", str(source))
    assert result["type"] == "zip"
    assert any(e["path"] == "readme.txt" for e in result["entries"])


@pytest.mark.skipif(shutil.which("zsteg") is None, reason="zsteg not installed")
def test_cli_zsteg_clean(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-zsteg")
    source = _write(challenge, "plain.png", png_bytes())
    result = _run_json(challenge, capsys, "tool", "zsteg", str(source))
    assert result["status"] == "clean"


@pytest.mark.skipif(shutil.which("capinfos") is None or shutil.which("tshark") is None, reason="tshark suite not installed")
def test_cli_pcap(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-pcap")
    source = _write(challenge, "cap.pcap", pcap_bytes())
    result = _run_json(challenge, capsys, "tool", "pcap", str(source))
    assert result["packet_count"] == "1"
    assert result["protocols"]


@pytest.mark.skipif(shutil.which("ROPgadget") is None, reason="ROPgadget not installed")
def test_cli_rop(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-rop")
    result = _run_json(challenge, capsys, "tool", "rop", "/bin/true", "--only", "pop|ret", "--max-gadgets", "20")
    assert result["gadget_count"] > 0
    assert result["gadget_count"] <= 20
    assert result["gadgets"][0]["address"] > 0


@pytest.mark.skipif(shutil.which("readelf") is None, reason="readelf not installed")
def test_cli_imports(tmp_path: Path, capsys):
    challenge = _init(tmp_path, "cli-imports")
    result = _run_json(challenge, capsys, "tool", "imports", "/bin/true")
    assert result["import_count"] > 0
    assert any(i["name"] == "__gmon_start__" for i in result["imports"])


@pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf not installed")
def test_cli_ffuf_scope_gate(tmp_path: Path, capsys):
    """Out-of-scope ffuf is refused by the CLI with a non-zero exit."""
    challenge = _init(tmp_path, "cli-ffuf-scope")
    wordlist = challenge / "work" / "words.txt"
    wordlist.parent.mkdir(parents=True, exist_ok=True)
    wordlist.write_text("admin\n", encoding="utf-8")
    rc = main(["-C", str(challenge), "tool", "ffuf", "http://127.0.0.1:1/FUZZ", "--wordlist", str(wordlist)])
    assert rc != 0
