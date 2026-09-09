#!/usr/bin/env python3
"""Deterministic driver: undo the single-byte XOR (0x42) and print the flag."""
import argparse
import re
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    data = (challenge_dir / "original" / "secret.bin").read_bytes()
    flag_bytes = bytes(value ^ 0x42 for value in data)
    match = re.search(rb"flag\{[^}]+\}", flag_bytes)
    if not match:
        raise SystemExit("flag pattern not found after XOR")
    print(f"FLAG={match.group(0).decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
