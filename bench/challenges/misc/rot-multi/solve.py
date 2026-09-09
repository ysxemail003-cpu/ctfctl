#!/usr/bin/env python3
"""Deterministic driver: decode the two ROT13 layers."""
import argparse
import codecs
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
    text = (challenge_dir / "original" / "message.txt").read_text(encoding="utf-8").strip()
    for _ in range(2):
        text = codecs.decode(text, "rot13")
    match = re.search(r"flag\{[^}]+\}", text)
    if not match:
        raise SystemExit("flag pattern not found after ROT13 decode")
    print(f"FLAG={match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
