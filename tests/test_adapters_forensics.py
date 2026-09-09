"""Forensics adapter tests: exif, binwalk, archive, zsteg, pcap."""
from __future__ import annotations

import shutil
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from ctf_agent.adapters import forensics as forensics_adapter
from ctf_agent.challenge import init_challenge
from ctf_agent.errors import CTFError


def _challenge(tmp_path: Path, name: str = "forensics") -> Path:
    return init_challenge(tmp_path, "demo", name, "forensics", "AI_NATIVE", confirm_authorization=True)


def _png_bytes(width: int = 8, height: int = 8) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    sig = b"\x89PNG\r\n\x1a\n"
    raw = b"".join(b"\x00" + bytes([200, 30, 30] * width) for _ in range(height))
    return (
        sig
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def _zip_bytes() -> bytes:
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("readme.txt", "hello secret")
        zf.writestr("data/flag_hint.txt", "keep looking")
    return buffer.getvalue()


def _pcap_bytes() -> bytes:
    payload = b"GET / HTTP/1.0\r\n\r\n"
    eth = b"\x00" * 12
    total = 20 + 20 + len(payload)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", total)
        + b"\x00\x01\x00\x00\x40\x06\x00\x00"
        + bytes([10, 0, 0, 1])
        + bytes([10, 0, 0, 2])
    )
    ip += struct.pack(">H", 0)  # checksum placeholder (not validated by tools here)

    def _csum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total_sum = sum(struct.unpack(f">{len(data) // 2}H", data))
        while total_sum >> 16:
            total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)
        return (~total_sum) & 0xFFFF

    ip = ip[:10] + struct.pack(">H", _csum(ip)) + ip[12:]
    tcp = struct.pack(">HHII", 12345, 80, 0, 0) + b"\x50\x18\x00\x00\x00\x00\x00\x00"
    pseudo = bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2]) + b"\x00\x06" + struct.pack(">H", len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack(">H", _csum(pseudo + tcp + payload)) + tcp[18:]
    frame = eth + ip + tcp + payload
    header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    return header + struct.pack("<IIII", 0, len(frame), len(frame), len(frame)) + frame


# --- exif ---


@pytest.mark.skipif(shutil.which("exiftool") is None, reason="exiftool not installed")
def test_exif_reads_png_metadata(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-exif")
    source = challenge / "work" / "pic.png"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_png_bytes())
    result = forensics_adapter.exif(challenge, source)
    assert result["tags"].get("FileType") == "PNG"
    assert result["tag_count"] > 0
    assert result["logs"]["exiftool"].startswith("LOG-")


def test_exif_rejects_missing_input(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-exif-missing")
    with pytest.raises(CTFError):
        forensics_adapter.exif(challenge, challenge / "work" / "nope.png")


# --- binwalk ---


@pytest.mark.skipif(shutil.which("binwalk") is None, reason="binwalk not installed")
def test_binwalk_finds_embedded_zip(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-binwalk")
    source = challenge / "work" / "pic_with_zip.png"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_png_bytes() + _zip_bytes())
    result = forensics_adapter.binwalk_scan(challenge, source)
    assert any("Zip archive" in entry["description"] for entry in result["entries"])
    assert result["extracted"] is None  # read-only by default
    assert result["logs"]["scan"].startswith("LOG-")


@pytest.mark.skipif(shutil.which("binwalk") is None, reason="binwalk not installed")
def test_binwalk_extract_lands_in_work(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-binwalk-x")
    source = challenge / "work" / "carrier.png"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_png_bytes() + _zip_bytes())
    result = forensics_adapter.binwalk_scan(challenge, source, extract=True)
    extracted = result["extracted"]
    assert extracted is not None
    assert extracted["file_count"] >= 1
    assert "work" in extracted["directory"]
    assert result["logs"]["extract"].startswith("LOG-")


# --- archive ---


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")
def test_archive_list_zip_members(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-7z")
    source = challenge / "work" / "arch.zip"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_zip_bytes())
    result = forensics_adapter.archive_list(challenge, source)
    assert result["type"] == "zip"
    paths = [entry["path"] for entry in result["entries"]]
    assert "readme.txt" in paths
    assert "data/flag_hint.txt" in paths
    assert result["logs"]["7z"].startswith("LOG-")


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")
def test_archive_list_rejects_non_archive(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-7z-bad")
    source = challenge / "work" / "not.zip"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_png_bytes())
    with pytest.raises(CTFError):
        forensics_adapter.archive_list(challenge, source)


# --- zsteg ---


@pytest.mark.skipif(shutil.which("zsteg") is None, reason="zsteg not installed")
def test_zsteg_clean_png(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-zsteg-clean")
    source = challenge / "work" / "plain.png"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_png_bytes())
    result = forensics_adapter.zsteg_detect(challenge, source)
    assert result["status"] == "clean"
    assert result["findings"] == []
    assert result["logs"]["zsteg"].startswith("LOG-")


def _png_without_idat(width: int = 1, height: int = 1) -> bytes:
    """A structurally invalid PNG (no IDAT) that makes zsteg crash."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    sig = b"\x89PNG\r\n\x1a\n"
    return (
        sig
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IEND", b"")
    )


@pytest.mark.skipif(shutil.which("zsteg") is None, reason="zsteg not installed")
def test_zsteg_reports_tool_error_on_degenerate_image(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-zsteg-degenerate")
    source = challenge / "work" / "broken.png"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_png_without_idat())
    result = forensics_adapter.zsteg_detect(challenge, source)
    assert result["status"] == "error"
    assert result["error"]
    assert result["logs"]["zsteg"].startswith("LOG-")


# --- pcap ---


@pytest.mark.skipif(shutil.which("capinfos") is None or shutil.which("tshark") is None, reason="tshark suite not installed")
def test_pcap_summary(tmp_path: Path):
    challenge = _challenge(tmp_path, "fx-pcap")
    source = challenge / "work" / "cap.pcap"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_pcap_bytes())
    result = forensics_adapter.pcap_summary(challenge, source)
    assert result["packet_count"] == "1"
    assert result["protocols"], "protocol hierarchy should list at least frame"
    assert result["logs"]["capinfos"].startswith("LOG-")
    assert result["logs"]["tshark"].startswith("LOG-")
