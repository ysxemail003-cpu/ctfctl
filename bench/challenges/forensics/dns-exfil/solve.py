#!/usr/bin/env python3
"""Deterministic driver: parse the DNS query name out of the pcap."""
import argparse
import re
import struct
import sys
from pathlib import Path


def extract_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            return ".".join(labels), offset
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    raw = (challenge_dir / "original" / "capture.pcap").read_bytes()
    # Skip pcap global header (24) + per-packet header (16) + eth(14) + ip(20) + udp(8)
    packet = raw[24 + 16:]
    dns_offset = 14 + 20 + 8
    qname, _ = extract_qname(packet, dns_offset + 12)  # +12 = DNS header
    match = re.search(r"flag\{[^}]+\}", qname)
    if not match:
        raise SystemExit(f"no flag in qname: {qname!r}")
    print(f"FLAG={match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
