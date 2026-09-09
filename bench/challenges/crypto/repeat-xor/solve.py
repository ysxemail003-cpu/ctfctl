#!/usr/bin/env python3
"""Deterministic driver: recover the repeating key via the known 'flag{' prefix."""
import argparse
import re
import sys
from pathlib import Path


def decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    ciphertext = bytes.fromhex((challenge_dir / "original" / "cipher.hex").read_text().strip())
    prefix = b"flag{"
    for length in range(1, min(len(prefix), 8) + 1):
        key = bytes(ciphertext[i] ^ prefix[i] for i in range(length))
        plaintext = decrypt(ciphertext, key)
        match = re.search(rb"flag\{[^}]+\}", plaintext)
        if match:
            print(f"FLAG={match.group(0).decode()}")
            return 0
    raise SystemExit("no flag recovered")


if __name__ == "__main__":
    raise SystemExit(main())
