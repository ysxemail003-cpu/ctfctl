"""Crypto adapter tests: hash identification and local cracking."""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from ctf_agent.adapters import crypto as crypto_adapter
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError

MD5_PASSWORD = hashlib.md5(b"password").hexdigest()  # 5f4dcc3b...


def _challenge(tmp_path: Path, name: str = "crypto") -> Path:
    return init_challenge(tmp_path, "demo", name, "crypto", "AI_NATIVE", confirm_authorization=True)


def _wordlist(challenge: Path, words: list[str], name: str = "words.txt") -> Path:
    path = challenge / "work" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


# --- offline shape classification (always runs, no external tool) ---


def test_classify_hash_shape_common_families():
    assert crypto_adapter.classify_hash_shape(MD5_PASSWORD)["family"] == "md5-hex"
    assert crypto_adapter.classify_hash_shape("a" * 40)["family"] == "sha1-hex"
    assert crypto_adapter.classify_hash_shape("a" * 64)["family"] == "sha256-hex"
    bcrypt = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    assert crypto_adapter.classify_hash_shape(bcrypt)["family"] == "bcrypt"
    unknown = crypto_adapter.classify_hash_shape("not-a-hash")
    assert unknown["family"] == "unknown"


def test_identify_hash_rejects_unsafe_characters(tmp_path: Path):
    challenge = _challenge(tmp_path)
    with pytest.raises(CTFError):
        crypto_adapter.identify_hash(challenge, "abc; rm -rf /")


def test_identify_hash_heuristic_without_hashid(tmp_path: Path, monkeypatch):
    challenge = _challenge(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "hashid" else "/usr/bin/" + name)
    result = crypto_adapter.identify_hash(challenge, MD5_PASSWORD)
    assert result["shape"]["family"] == "md5-hex"
    assert result["note"] == "hashid not installed; shape heuristic only."
    assert result["candidates"] == []
    assert result["logs"] == {}


@pytest.mark.skipif(shutil.which("hashid") is None, reason="hashid not installed")
def test_identify_hash_md5_with_hashid(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-hashid")
    result = crypto_adapter.identify_hash(challenge, MD5_PASSWORD)
    assert result["length"] == 32
    assert result["candidates"], "hashid returned no candidates"
    names = [c["name"].lower() for c in result["candidates"]]
    assert any("md5" in name for name in names)
    assert any(c.get("hashcat_mode") == 0 for c in result["candidates"])
    assert any(c.get("john_format") == "raw-md5" for c in result["candidates"])
    assert result["suggested"] is not None
    assert "md5" in result["suggested"]["name"].lower()  # shape heuristic prefers MD5 over MD2
    assert result["suggested"]["hashcat_mode"] == 0
    assert result["suggested"]["john_format"] == "raw-md5"
    assert result["logs"]["hashid"].startswith("LOG-")


# --- argument validation ---


def test_crack_requires_wordlist(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-nowl")
    with pytest.raises(CTFError):
        crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD)


def test_crack_requires_exactly_one_hash_source(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-onearg")
    words = _wordlist(challenge, ["password"])
    with pytest.raises(CTFError):
        crypto_adapter.crack_hash(challenge, wordlist=words)
    with pytest.raises(CTFError):
        crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD, hash_file=words, wordlist=words)


def test_crack_rejects_unsafe_hash(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-unsafe")
    words = _wordlist(challenge, ["password"])
    with pytest.raises(CTFError):
        crypto_adapter.crack_hash(challenge, value="$(touch pwned)", wordlist=words)


def test_crack_unsupported_tool(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-tool")
    words = _wordlist(challenge, ["password"])
    with pytest.raises(CTFError):
        crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD, wordlist=words, tool="md5sum")


@pytest.mark.skipif(shutil.which("hashcat") is None, reason="hashcat not installed")
def test_crack_hashcat_requires_inferable_mode(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-mode")
    words = _wordlist(challenge, ["password"])
    with pytest.raises(CTFError):
        crypto_adapter.crack_hash(challenge, value="not-a-known-shape", wordlist=words, tool="hashcat")


# --- john end-to-end (installed on Kali; skipped elsewhere) ---


@pytest.mark.skipif(shutil.which("john") is None, reason="john not installed")
def test_crack_john_cracked_md5(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-john-ok")
    words = _wordlist(challenge, ["wrong", "password"])
    result = crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD, wordlist=words, tool="john")
    assert result["status"] == "cracked"
    assert "password" in result["plaintexts"]
    assert result["logs"]["crack"].startswith("LOG-")
    assert result["logs"]["show"].startswith("LOG-")
    assert (challenge / result["artifacts"]["hash_file"]).is_file()


@pytest.mark.skipif(shutil.which("john") is None, reason="john not installed")
def test_crack_john_not_cracked(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-john-no")
    words = _wordlist(challenge, ["wrongword"])
    result = crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD, wordlist=words, tool="john")
    assert result["status"] == "not_cracked"
    assert result["plaintexts"] == []


@pytest.mark.skipif(shutil.which("hashcat") is None, reason="hashcat not installed")
@pytest.mark.skipif(not os.environ.get("CTF_TEST_HASHCAT"), reason="slow (~25s); set CTF_TEST_HASHCAT=1")
def test_crack_hashcat_cracked_md5(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-hashcat-ok")
    words = _wordlist(challenge, ["password"])
    result = crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD, wordlist=words, tool="hashcat")
    assert result["status"] == "cracked"
    assert "password" in result["plaintexts"]


@pytest.mark.skipif(shutil.which("john") is None, reason="john not installed")
def test_crack_john_with_hash_file(tmp_path: Path):
    challenge = _challenge(tmp_path, "crypto-john-file")
    words = _wordlist(challenge, ["password"])
    source = challenge / "work" / "hashes.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(MD5_PASSWORD + "\n", encoding="utf-8")
    result = crypto_adapter.crack_hash(challenge, hash_file=source, wordlist=words, tool="john")
    assert result["status"] == "cracked"
    assert "password" in result["plaintexts"]
    assert (challenge / result["artifacts"]["hash_file"]).is_file()


def test_crack_hashcat_parses_pot_with_stubbed_runner(tmp_path: Path, monkeypatch):
    """Exercise the hashcat branch and pot parsing without launching hashcat
    (its OpenCL startup is ~20s; real invocation is covered by CTF_TEST_HASHCAT)."""
    challenge = _challenge(tmp_path, "crypto-hashcat-parse")
    words = _wordlist(challenge, ["password"])
    out_file = challenge / "work" / "hashes" / f"{MD5_PASSWORD}.hashcat.out"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(f"{MD5_PASSWORD}:password\n", encoding="utf-8")
    monkeypatch.setattr(crypto_adapter, "run_command", lambda *a, **k: {"id": "LOG-000099"})
    monkeypatch.setattr(
        crypto_adapter.shutil,
        "which",
        lambda name: f"/usr/bin/{name}",
    )
    result = crypto_adapter.crack_hash(challenge, value=MD5_PASSWORD, wordlist=words, tool="hashcat")
    assert result["status"] == "cracked"
    assert "password" in result["plaintexts"]
    assert result["logs"]["crack"] == "LOG-000099"
