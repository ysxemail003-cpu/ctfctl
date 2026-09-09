#!/usr/bin/env python3
"""Deterministic driver: read the flag from the X-Bench-Flag response header."""
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
    parser.add_argument("--target-url", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir
    result = ctfctl(challenge_dir, args.ctfctl, "tool", "http", args.target_url)
    headers = result.get("headers") or {}
    value = next((v for k, v in headers.items() if k.lower() == "x-bench-flag"), None)
    if not value:
        raise SystemExit(f"X-Bench-Flag header not found; headers={json.dumps(headers)}")
    print(f"FLAG={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
