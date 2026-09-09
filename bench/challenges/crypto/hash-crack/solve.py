#!/usr/bin/env python3
"""Deterministic driver: identify the hash, crack it with john, print the flag."""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def ctfctl(challenge_dir: Path, ctfctl: str, *args):
    proc = subprocess.run([ctfctl, "-C", str(challenge_dir), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"ctfctl {' '.join(args)} failed: {(proc.stderr or '')[-400:]}")
    return json.loads(proc.stdout or "{}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    hash_value = (challenge_dir / "original" / "hash.txt").read_text(encoding="utf-8").strip()
    ctfctl(challenge_dir, args.ctfctl, "tool", "hashid", hash_value)
    wordlist = args.root / "support" / "words.txt"
    result = ctfctl(challenge_dir, args.ctfctl, "tool", "crack", hash_value, "--wordlist", str(wordlist), "--tool", "john")
    if result.get("status") != "cracked" or not result.get("plaintexts"):
        raise SystemExit(f"hash not cracked: {result.get('status')}")
    print(f"FLAG=flag{{{result['plaintexts'][0]}}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
