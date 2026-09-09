#!/usr/bin/env python3
"""Deterministic driver: find the XOR(0x11) blob inside the ELF and decode it."""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def ctfctl(challenge_dir: Path, ctfctl: str, *args):
    proc = subprocess.run([ctfctl, "-C", str(challenge_dir), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"ctfctl {' '.join(args)} failed: {(proc.stderr or '')[-400:]}")
    return json.loads(proc.stdout or "{}")


def find_xored_flag(data: bytes, key: int) -> str | None:
    needle = bytes(b ^ key for b in b"flag{")
    index = data.find(needle)
    if index == -1:
        return None
    end = index
    while end < len(data) and data[end] != (ord("}") ^ key) and end - index < 256:
        end += 1
    if end >= len(data):
        return None
    decoded = bytes(b ^ key for b in data[index:end + 1]).decode(errors="replace")
    return decoded if re.fullmatch(r"flag\{[^}]+\}", decoded) else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    prog = challenge_dir / "original" / "prog"
    ctfctl(challenge_dir, args.ctfctl, "tool", "file", str(prog))
    flag = find_xored_flag(prog.read_bytes(), 0x11)
    if not flag:
        raise SystemExit("xored flag blob not found in ELF")
    print(f"FLAG={flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
