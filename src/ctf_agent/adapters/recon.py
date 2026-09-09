from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command
from ..state import StateStore
from ..util import sha256_file
from . import elf as elf_adapter


def _safe_name(path: Path) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "-" for char in path.name.lower())[:100] or "input"


def _stdout(challenge_dir: Path, metadata: dict[str, Any]) -> str:
    path = challenge_dir / str(metadata.get("stdout_file", ""))
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def file_recon(challenge_dir: Path, input_path: Path, timeout: float = 60.0) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    input_path = input_path.expanduser()
    if not input_path.is_absolute():
        input_path = challenge_dir / input_path
    input_path = input_path.resolve()
    if not input_path.is_file():
        raise CTFError(f"Input file not found: {input_path}")

    file_meta = run_command(
        challenge_dir,
        ["file", str(input_path)],
        f"file-{_safe_name(input_path)}",
        "file-recon",
        timeout=timeout,
        quiet=True,
    )
    sha_meta = run_command(
        challenge_dir,
        ["sha256sum", str(input_path)],
        f"sha256-{_safe_name(input_path)}",
        "file-recon",
        timeout=timeout,
        quiet=True,
    )
    strings_meta = run_command(
        challenge_dir,
        ["strings", "-n", "6", str(input_path)],
        f"strings-{_safe_name(input_path)}",
        "file-recon",
        timeout=timeout,
        quiet=True,
    )

    file_text = _stdout(challenge_dir, file_meta).strip()
    sha_text = _stdout(challenge_dir, sha_meta)
    strings_text = _stdout(challenge_dir, strings_meta)
    lowered = file_text.lower()
    result: dict[str, Any] = {
        "schema_version": 1,
        "path": str(input_path),
        "name": input_path.name,
        "size": input_path.stat().st_size,
        "sha256": sha_text.split()[0] if sha_text.split() else sha256_file(input_path),
        "file": file_text,
        "logs": {
            "file": file_meta["id"],
            "sha256": sha_meta["id"],
            "strings": strings_meta["id"],
        },
        "interesting_strings": [line.strip() for line in strings_text.splitlines() if line.strip()][:100],
    }

    if "elf" in lowered:
        result["elf"] = elf_adapter.recon(challenge_dir, input_path, timeout=timeout)
        result["kind"] = "elf"
        result["suggested_next_action"] = "Copy the binary to work/, run it locally with controlled input, then inspect key functions"
    elif any(value in lowered for value in ("zip archive", "tar archive", "gzip", "bzip2", "xz", "7-zip")):
        result["kind"] = "archive"
        lister = shutil.which("7z") or shutil.which("7zz")
        if lister:
            archive_meta = run_command(
                challenge_dir,
                [lister, "l", str(input_path)],
                f"archive-list-{_safe_name(input_path)}",
                "file-recon",
                timeout=timeout,
                quiet=True,
            )
            result["archive_listing"] = _stdout(challenge_dir, archive_meta)
            result["logs"]["archive_listing"] = archive_meta["id"]
        result["suggested_next_action"] = "List and extract the archive into work/, then inventory extracted files"
    elif "pcap" in lowered or input_path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
        result["kind"] = "pcap"
        capinfos = shutil.which("capinfos")
        if capinfos:
            pcap_meta = run_command(
                challenge_dir,
                [capinfos, str(input_path)],
                f"capinfos-{_safe_name(input_path)}",
                "file-recon",
                timeout=timeout,
                quiet=True,
            )
            result["capinfos"] = _stdout(challenge_dir, pcap_meta)
            result["logs"]["capinfos"] = pcap_meta["id"]
        result["suggested_next_action"] = "Inspect conversations, protocols, HTTP objects, credentials, and transferred files"
    elif any(value in lowered for value in ("image", "png", "jpeg", "jpg", "gif", "bitmap")):
        result["kind"] = "image"
        exiftool = shutil.which("exiftool")
        if exiftool:
            image_meta = run_command(
                challenge_dir,
                [exiftool, str(input_path)],
                f"exiftool-{_safe_name(input_path)}",
                "file-recon",
                timeout=timeout,
                quiet=True,
            )
            result["exiftool"] = _stdout(challenge_dir, image_meta)
            result["logs"]["exiftool"] = image_meta["id"]
        result["suggested_next_action"] = "Check metadata, appended data, color/channel anomalies, and steganography tools"
    else:
        result["kind"] = "file"
        result["suggested_next_action"] = "Inspect format, encodings, embedded metadata, and relevant parser behavior"

    output_dir = challenge_dir / "artifacts" / "recon"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{_safe_name(input_path)}.json"
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    StateStore(challenge_dir).event("file_recon", result)
    return result
