"""Shared binary fixtures for adapter and CLI tests (all self-contained)."""
from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib

MD5_PASSWORD = hashlib.md5(b"password").hexdigest()


def _chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def png_bytes(width: int = 8, height: int = 8) -> bytes:
    """A valid minimal RGB PNG (no external tools needed to build it)."""
    sig = b"\x89PNG\r\n\x1a\n"
    raw = b"".join(b"\x00" + bytes([200, 30, 30] * width) for _ in range(height))
    return (
        sig
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(raw))
        + _chunk(b"IEND", b"")
    )


def png_without_idat(width: int = 1, height: int = 1) -> bytes:
    """A structurally broken PNG (no IDAT) that makes zsteg crash."""
    sig = b"\x89PNG\r\n\x1a\n"
    return (
        sig
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _chunk(b"IEND", b"")
    )


def zip_bytes() -> bytes:
    """A zip containing readme.txt and data/flag_hint.txt."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("readme.txt", "hello secret")
        zf.writestr("data/flag_hint.txt", "keep looking")
    return buffer.getvalue()


def pcap_bytes() -> bytes:
    """A single-frame Ethernet/IP/TCP pcap with a GET payload."""
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
