#!/usr/bin/env python3
"""Deterministic driver: carve the appended zip with binwalk and read flag.txt."""
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
    carrier = challenge_dir / "original" / "carrier.png"
    result = ctfctl(challenge_dir, args.ctfctl, "tool", "binwalk", str(carrier), "--extract")
    extracted = result.get("extracted")
    if not extracted:
        raise SystemExit("binwalk found nothing to extract")
    flag_path = next((Path(extracted["directory"]) / rel for rel in extracted["files"] if rel.endswith("flag.txt")), None)
    if flag_path is None:
        raise SystemExit(f"flag.txt not found in {extracted['files']}")
    flag = (challenge_dir / flag_path).read_text(encoding="utf-8").strip()
    print(f"FLAG={flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
