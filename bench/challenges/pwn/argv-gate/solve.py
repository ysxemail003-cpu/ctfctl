#!/usr/bin/env python3
"""Deterministic driver: find the gate password via file/strings recon, then run the ELF."""
import argparse
import json
import re
import shutil
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

    work_gate = challenge_dir / "work" / "gate"
    work_gate.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(challenge_dir / "original" / "gate", work_gate)
    work_gate.chmod(0o755)

    recon = ctfctl(challenge_dir, args.ctfctl, "tool", "file", str(work_gate))
    password = next(
        (s for s in recon.get("interesting_strings", []) if "s3cr3t_pw" in s),
        None,
    )
    if not password:
        raise SystemExit("password token not found in recon strings")

    run = subprocess.run(
        [args.ctfctl, "-C", str(challenge_dir), "run", "--tag", "gate-run", "--", str(work_gate), password],
        capture_output=True,
        text=True,
    )
    match = re.search(r"flag\{[^}]+\}", run.stdout or "")
    if not match:
        raise SystemExit(f"no flag in gate output: {(run.stdout or '')[-400:]}")
    print(f"FLAG={match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
