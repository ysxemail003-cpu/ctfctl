from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command
from ..state import StateStore
from ..util import sha256_file


def recon(challenge_dir: Path, binary: Path, timeout: float = 30.0) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    binary = binary.expanduser()
    if not binary.is_absolute():
        binary = challenge_dir / binary
    binary = binary.resolve()
    if not binary.is_file():
        raise CTFError(f"Binary not found: {binary}")
    if challenge_dir not in binary.parents and binary.parent != challenge_dir:
        # Still allow absolute paths, but require the caller to know what they are doing.
        pass

    file_meta = run_command(challenge_dir, ["file", str(binary)], "elf-file", "pwn-recon", timeout=timeout, quiet=True)
    checksec_meta = run_command(
        challenge_dir,
        ["checksec", f"--file={binary}", "--format=json"],
        "elf-checksec",
        "pwn-recon",
        timeout=timeout,
        quiet=True,
    )
    sha_meta = run_command(challenge_dir, ["sha256sum", str(binary)], "elf-sha256", "pwn-recon", timeout=timeout, quiet=True)
    readelf_meta = run_command(
        challenge_dir,
        ["readelf", "-h", str(binary)],
        "elf-readelf-header",
        "pwn-recon",
        timeout=timeout,
        quiet=True,
    )

    def output(meta: dict[str, Any]) -> str:
        return (challenge_dir / meta["stdout_file"]).read_text(encoding="utf-8", errors="replace")

    file_text = output(file_meta)
    checksec_text = output(checksec_meta)
    sha_text = output(sha_meta)
    readelf_text = output(readelf_meta)

    result: dict[str, Any] = {
        "binary": str(binary),
        "file": file_text.strip(),
        "sha256": sha_text.split()[0] if sha_text.split() else sha256_file(binary),
        "logs": {
            "file": file_meta["id"],
            "checksec": checksec_meta["id"],
            "sha256": sha_meta["id"],
            "readelf": readelf_meta["id"],
        },
    }

    if "ELF 64-bit" in file_text:
        result["bits"] = 64
    elif "ELF 32-bit" in file_text:
        result["bits"] = 32
    if "x86-64" in file_text or "AMD64" in file_text:
        result["arch"] = "amd64"
    elif "Intel 80386" in file_text or "x86" in file_text:
        result["arch"] = "x86"
    elif "ARM aarch64" in file_text:
        result["arch"] = "aarch64"
    elif "ARM" in file_text:
        result["arch"] = "arm"
    lowered_file = file_text.lower()
    result["endian"] = (
        "little" if "little endian" in lowered_file or " lsb" in lowered_file
        else "big" if "big endian" in lowered_file or " msb" in lowered_file
        else None
    )
    result["static"] = "statically linked" in file_text
    result["stripped"] = "stripped" in file_text or "not stripped" not in file_text

    try:
        checksec_json = json.loads(checksec_text)
        values = next(iter(checksec_json.values()))
        result["relro"] = values.get("relro")
        result["canary"] = str(values.get("canary")).lower() not in {"no", "false", "none"}
        result["nx"] = str(values.get("nx")).lower() not in {"no", "false", "disabled"}
        result["pie"] = str(values.get("pie")).lower() not in {"no", "false", "none"}
        result["symbols"] = str(values.get("symbols")).lower() not in {"no", "false", "none"}
    except (json.JSONDecodeError, StopIteration, TypeError):
        for key in ("RELRO", "Canary", "NX", "PIE"):
            match = re.search(rf"{key}:\s*([^\s]+)", checksec_text, re.IGNORECASE)
            if match:
                value = match.group(1)
                if key == "Canary":
                    result["canary"] = value.lower() != "no"
                elif key == "NX":
                    result["nx"] = value.lower() != "disabled"
                elif key == "PIE":
                    result["pie"] = value.lower() != "no"
                else:
                    result["relro"] = value

    for key in ("Type:", "Machine:", "Entry point address:"):
        match = re.search(rf"{re.escape(key)}\s+([^\n]+)", readelf_text)
        if match:
            result[{"Type:": "elf_type", "Machine:": "machine", "Entry point address:": "entry_point"}[key]] = match.group(1).strip()

    output_path = challenge_dir / "artifacts" / "elf-recon.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    StateStore(challenge_dir).event("elf_recon", result)
    return result
