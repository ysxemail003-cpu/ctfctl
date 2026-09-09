"""Structured pwn/rev helper adapters: ROP gadgets and dynamic imports.

Phase A4 helpers. These are read-only analysis commands:

- ``rop_gadgets``: ROPgadget output parsed into structured gadgets.
- ``dyn_imports``: imported (UND) symbols from ``readelf --dyn-syms``, useful
  for libc/plt planning before writing an exploit.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command

_GADGET_LINE = re.compile(r"^0x([0-9a-fA-F]+)\s+:\s+(.*)$")
_UND_SYMBOL = re.compile(r"^\s*\d+:\s+[0-9a-fA-F]+\s+\d+\s+\S+\s+\S+\s+\S+\s+UND\s+(\S+?)(?:\s+\(\d+\))?\s*$")


def _require_tool(name: str) -> None:
    if not shutil.which(name):
        raise CTFError(f"{name} is not installed or not in PATH.")


def _stdout(challenge_dir: Path, metadata: dict[str, Any]) -> str:
    path = challenge_dir / str(metadata.get("stdout_file", ""))
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _resolve_binary(challenge_dir: Path, binary: Path) -> Path:
    binary = binary.expanduser()
    if not binary.is_absolute():
        binary = challenge_dir / binary
    binary = binary.resolve()
    if not binary.is_file():
        raise CTFError(f"Binary file not found: {binary}")
    return binary


def rop_gadgets(
    challenge_dir: Path,
    binary: Path,
    only: str | None = None,
    depth: int = 8,
    max_gadgets: int = 300,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """List ROP gadgets for an ELF, optionally filtered by instruction keywords.

    Output is capped at ``max_gadgets`` entries; the full transcript stays in
    the LOG stdout file for offline review. ``only`` and ``depth`` are passed
    straight to ROPgadget and are the agent's responsibility to tune.
    """
    challenge_dir = challenge_dir.resolve()
    _require_tool("ROPgadget")
    source = _resolve_binary(challenge_dir, binary)
    argv = ["ROPgadget", "--binary", str(source), "--depth", str(int(depth))]
    if only:
        argv += ["--only", only]

    metadata = run_command(
        challenge_dir,
        argv,
        f"rop-{source.stem}",
        "pwn-recon",
        timeout=timeout,
        quiet=True,
    )
    gadgets: list[dict[str, Any]] = []
    for line in _stdout(challenge_dir, metadata).splitlines():
        match = _GADGET_LINE.match(line.strip())
        if match:
            gadgets.append({"address": int(match.group(1), 16), "gadget": match.group(2).strip()})
            if len(gadgets) >= max_gadgets:
                break

    return {
        "schema_version": 1,
        "tool": "ROPgadget",
        "source": source.name,
        "only": only,
        "depth": int(depth),
        "gadget_count": len(gadgets),
        "gadgets": gadgets,
        "logs": {"ropgadget": metadata["id"]},
    }


def dyn_imports(challenge_dir: Path, binary: Path, timeout: float = 60.0) -> dict[str, Any]:
    """List dynamically imported (undefined) symbols via readelf --dyn-syms."""
    challenge_dir = challenge_dir.resolve()
    _require_tool("readelf")
    source = _resolve_binary(challenge_dir, binary)
    metadata = run_command(
        challenge_dir,
        ["readelf", "--dyn-syms", "-W", str(source)],
        f"dynsyms-{source.stem}",
        "pwn-recon",
        timeout=timeout,
        quiet=True,
    )
    imports: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in _stdout(challenge_dir, metadata).splitlines():
        match = _UND_SYMBOL.match(line.strip())
        if not match:
            continue
        symbol = match.group(1)
        name, _, version = symbol.partition("@")
        if name in seen or not name:
            continue
        seen.add(name)
        imports.append({"name": name, "version": version or None})
    imports.sort(key=lambda item: item["name"])
    return {
        "schema_version": 1,
        "tool": "readelf",
        "source": source.name,
        "import_count": len(imports),
        "imports": imports,
        "logs": {"readelf": metadata["id"]},
    }
