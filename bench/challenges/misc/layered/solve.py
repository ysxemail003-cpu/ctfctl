#!/usr/bin/env python3
"""Deterministic driver: unwrap gzip > zip > ROT13 and print the flag."""
import argparse
import codecs
import gzip
import io
import re
import sys
import zipfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    bundle = (challenge_dir / "original" / "bundle.bin").read_bytes()
    with zipfile.ZipFile(io.BytesIO(gzip.decompress(bundle))) as archive:
        text = archive.read("flag_hint.txt").decode()
    decoded = codecs.decode(text, "rot13")
    match = re.search(r"flag\{[^}]+\}", decoded)
    if not match:
        raise SystemExit(f"flag not found after unwrap: {decoded!r}")
    print(f"FLAG={match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
