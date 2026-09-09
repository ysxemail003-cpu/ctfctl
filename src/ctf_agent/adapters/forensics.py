"""Structured forensics adapters for common evidence triage on Kali.

Coverage in this module (docs/CAPABILITY_PLAN.md Phase A2):

- ``exif``: exiftool JSON metadata (read-only).
- ``binwalk_scan``: signature/entropy scan; extraction is explicit and lands
  under ``work/extracted/``, never in ``original/``.
- ``archive_list``: 7z listing (``-slt``) of archives.
- ``zsteg_detect``: PNG/BMP steganography detection. zsteg crashes on some
  degenerate images, so non-zero exits are reported as ``status=error`` with a
  trimmed message instead of aborting the agent run.
- ``pcap_summary``: capinfos metadata plus a tshark protocol hierarchy.

Every command goes through ``runner.run_command`` (logged, hashed, budgeted,
capped). Inputs may be read from ``original/`` but are never written there.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command

_BINWALK_ENTRY = re.compile(r"^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.*)$")
_SLTPATH = re.compile(r"^Path\s*=\s*(.*)$")
_SLTSIZE = re.compile(r"^Size\s*=\s*(\d+)$")
_CAPINFO = re.compile(r"^\s*([^:]+?):\s+(.*)$")
_STDERR_TAIL = 1200
_FINDING_MARK = ".."


def _require_tool(name: str) -> None:
    if not shutil.which(name):
        raise CTFError(f"{name} is not installed or not in PATH.")


def _safe_name(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", path.name)[:80] or "input"


def _stdout(challenge_dir: Path, metadata: dict[str, Any]) -> str:
    path = challenge_dir / str(metadata.get("stdout_file", ""))
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _stderr(challenge_dir: Path, metadata: dict[str, Any]) -> str:
    path = challenge_dir / str(metadata.get("stderr_file", ""))
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _resolve_input(challenge_dir: Path, path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    path = path.resolve()
    if not path.is_file():
        raise CTFError(f"Input file not found: {path}")
    return path


def exif(challenge_dir: Path, path: Path, timeout: float = 60.0) -> dict[str, Any]:
    """Extract structured EXIF/metadata tags with exiftool (read-only)."""
    challenge_dir = challenge_dir.resolve()
    _require_tool("exiftool")
    source = _resolve_input(challenge_dir, path)
    metadata = run_command(
        challenge_dir,
        ["exiftool", "-json", str(source)],
        f"exif-{_safe_name(source)}",
        "forensics-recon",
        timeout=timeout,
        quiet=True,
    )
    tags: dict[str, Any] = {}
    try:
        parsed = json.loads(_stdout(challenge_dir, metadata) or "[]")
    except json.JSONDecodeError:
        parsed = []
    if isinstance(parsed, list) and parsed:
        raw = parsed[0] if isinstance(parsed[0], dict) else {}
        for key, value in raw.items():
            if key in ("SourceFile", "Directory"):
                continue
            if isinstance(value, (str, int, float)):
                text = str(value)
                if len(text) <= 300:
                    tags[key] = text
    return {
        "schema_version": 1,
        "tool": "exiftool",
        "source": source.name,
        "tag_count": len(tags),
        "tags": tags,
        "logs": {"exiftool": metadata["id"]},
    }


def binwalk_scan(
    challenge_dir: Path,
    path: Path,
    extract: bool = False,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Scan for embedded signatures with binwalk; optional explicit extraction."""
    challenge_dir = challenge_dir.resolve()
    _require_tool("binwalk")
    source = _resolve_input(challenge_dir, path)
    scan_meta = run_command(
        challenge_dir,
        ["binwalk", str(source)],
        f"binwalk-{_safe_name(source)}",
        "forensics-recon",
        timeout=timeout,
        quiet=True,
    )
    entries: list[dict[str, Any]] = []
    for line in _stdout(challenge_dir, scan_meta).splitlines():
        match = _BINWALK_ENTRY.match(line)
        if match:
            entries.append({"offset": int(match.group(1)), "description": match.group(2).strip()})

    result: dict[str, Any] = {
        "schema_version": 1,
        "tool": "binwalk",
        "source": source.name,
        "entries": entries,
        "extracted": None,
        "logs": {"scan": scan_meta["id"]},
    }
    if extract:
        out_dir = challenge_dir / "work" / "extracted" / _safe_name(source)
        out_dir.mkdir(parents=True, exist_ok=True)
        extract_meta = run_command(
            challenge_dir,
            ["binwalk", "-e", "-C", str(out_dir), str(source)],
            f"binwalk-extract-{_safe_name(source)}",
            "forensics-extract",
            timeout=timeout,
            quiet=True,
        )
        files = sorted(p.relative_to(out_dir).as_posix() for p in out_dir.rglob("*") if p.is_file())
        result["extracted"] = {
            "directory": str(out_dir.relative_to(challenge_dir)),
            "file_count": len(files),
            "files": files[:200],
        }
        result["logs"]["extract"] = extract_meta["id"]
    return result


def archive_list(challenge_dir: Path, path: Path, timeout: float = 60.0) -> dict[str, Any]:
    """List archive members and sizes with ``7z l -slt`` (read-only)."""
    challenge_dir = challenge_dir.resolve()
    _require_tool("7z")
    source = _resolve_input(challenge_dir, path)
    metadata = run_command(
        challenge_dir,
        ["7z", "l", "-slt", str(source)],
        f"7z-{_safe_name(source)}",
        "forensics-recon",
        timeout=timeout,
        quiet=True,
    )
    if int(metadata.get("exit_code", 0)) != 0:
        tail = _stderr(challenge_dir, metadata).strip().splitlines()[-6:]
        raise CTFError(f"7z could not list {source}: {'; '.join(tail)}")

    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    archive_type: str | None = None
    for line in _stdout(challenge_dir, metadata).splitlines():
        path_match = _SLTPATH.match(line)
        size_match = _SLTSIZE.match(line)
        type_match = re.match(r"^Type\s*=\s*(.*)$", line)
        if path_match:
            if current is not None and current.get("size") is not None:
                entries.append(current)
            current = {"path": path_match.group(1).strip(), "size": None}
        elif size_match and current is not None:
            current["size"] = int(size_match.group(1))
        elif type_match:
            archive_type = type_match.group(1).strip()
    if current is not None and current.get("size") is not None:
        entries.append(current)
    # The size-less container entry is the archive itself; members all carry a size.

    return {
        "schema_version": 1,
        "tool": "7z",
        "source": source.name,
        "type": archive_type,
        "member_count": len(entries),
        "entries": entries[:500],
        "logs": {"7z": metadata["id"]},
    }


def zsteg_detect(challenge_dir: Path, path: Path, timeout: float = 120.0) -> dict[str, Any]:
    """Detect LSB/extradata steganography in PNG/BMP with zsteg.

    zsteg returns non-zero and prints a Ruby traceback on some degenerate
    images (e.g. 1x1 PNGs). We report that as ``status=error`` with a trimmed
    message instead of failing the whole adapter, because "no stego here" and
    "tool choked on this image" are both useful signals to an agent.
    """
    challenge_dir = challenge_dir.resolve()
    _require_tool("zsteg")
    source = _resolve_input(challenge_dir, path)
    metadata = run_command(
        challenge_dir,
        ["zsteg", str(source)],
        f"zsteg-{_safe_name(source)}",
        "forensics-recon",
        timeout=timeout,
        quiet=True,
    )
    stdout = _stdout(challenge_dir, metadata)
    _ZSTEG_LINE = re.compile(r"^(\S+)\s+\.\.\s*(.*)$")
    findings: list[dict[str, str]] = []
    channels: list[str] = []
    for line in stdout.splitlines():
        match = _ZSTEG_LINE.match(line.strip())
        if not match:
            continue
        name, remainder = match.group(1), match.group(2)
        if name == "imagedata":
            # zsteg's generic "file:" guess on the whole image; not a stego finding.
            continue
        if remainder:
            findings.append({"channel": name, "result": remainder[:200]})
        else:
            channels.append(name)
    exit_code = int(metadata.get("exit_code", 0))
    status = "clean"
    error: str | None = None
    if exit_code != 0:
        status = "error"
        tail = _stderr(challenge_dir, metadata).strip().splitlines()[-8:]
        error = "; ".join(tail)[:_STDERR_TAIL]
    elif findings:
        status = "findings"
    return {
        "schema_version": 1,
        "tool": "zsteg",
        "source": source.name,
        "status": status,
        "channels_checked": len(channels),
        "findings": findings[:100],
        "error": error,
        "logs": {"zsteg": metadata["id"]},
    }


def pcap_summary(challenge_dir: Path, path: Path, timeout: float = 120.0) -> dict[str, Any]:
    """Summarize a pcap with capinfos metadata and a tshark protocol hierarchy."""
    challenge_dir = challenge_dir.resolve()
    _require_tool("capinfos")
    _require_tool("tshark")
    source = _resolve_input(challenge_dir, path)

    cap_meta = run_command(
        challenge_dir,
        ["capinfos", str(source)],
        f"capinfos-{_safe_name(source)}",
        "forensics-recon",
        timeout=timeout,
        quiet=True,
    )
    info: dict[str, Any] = {}
    for line in _stdout(challenge_dir, cap_meta).splitlines():
        match = _CAPINFO.match(line)
        if match and len(info) < 60:
            key = match.group(1).strip()
            value = match.group(2).strip()
            if key and value and not key.startswith(("Interface #", "Encapsulation =")):
                info[key] = value

    phs_meta = run_command(
        challenge_dir,
        ["tshark", "-r", str(source), "-q", "-z", "io,phs"],
        f"tshark-phs-{_safe_name(source)}",
        "forensics-recon",
        timeout=timeout,
        quiet=True,
    )
    protocols: list[str] = []
    for line in _stdout(challenge_dir, phs_meta).splitlines():
        stripped = line.strip()
        if stripped and "frames:" in stripped and not stripped.startswith(("=", "Filter")):
            protocols.append(stripped[:200])

    return {
        "schema_version": 1,
        "tool": "capinfos+tshark",
        "source": source.name,
        "packet_count": info.get("Number of packets"),
        "file_size": info.get("File size"),
        "capture_duration": info.get("Capture duration"),
        "info": info,
        "protocols": protocols[:40],
        "logs": {"capinfos": cap_meta["id"], "tshark": phs_meta["id"]},
    }
