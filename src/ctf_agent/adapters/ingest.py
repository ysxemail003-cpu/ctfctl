from __future__ import annotations

from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command
from ..state import StateStore
from ..util import sha256_file, utcnow
from . import recon as recon_adapter


def import_files(
    challenge_dir: Path,
    sources: list[Path],
    perform_recon: bool = True,
    timeout: float = 60.0,
) -> dict[str, Any]:
    challenge_dir = challenge_dir.resolve()
    original_dir = challenge_dir / "original"
    original_dir.mkdir(parents=True, exist_ok=True)
    imported: list[dict[str, Any]] = []

    for source in sources:
        source = source.expanduser().resolve()
        if not source.is_file():
            raise CTFError(f"Cannot import non-file or missing input: {source}")
        destination = original_dir / source.name
        source_hash = sha256_file(source)

        if destination.exists():
            destination_hash = sha256_file(destination)
            if destination_hash != source_hash:
                raise CTFError(
                    f"Refusing to overwrite existing original/{source.name}; content differs"
                )
            copied = False
        else:
            copy_meta = run_command(
                challenge_dir,
                ["cp", "--", str(source), str(destination)],
                f"import-{source.name}",
                "intake",
                timeout=timeout,
                quiet=True,
            )
            if copy_meta.get("exit_code") != 0:
                raise CTFError(f"Failed to import {source}")
            copied = True
            destination.chmod(0o444)

        record: dict[str, Any] = {
            "source": str(source),
            "destination": str(destination.relative_to(challenge_dir)),
            "sha256": source_hash,
            "size": source.stat().st_size,
            "copied": copied,
            "timestamp": utcnow(),
        }
        if perform_recon:
            record["recon"] = recon_adapter.file_recon(challenge_dir, destination, timeout=timeout)
        imported.append(record)

    result = {
        "schema_version": 1,
        "imported": imported,
        "count": len(imported),
        "original_dir": str(original_dir.relative_to(challenge_dir)),
    }
    StateStore(challenge_dir).event("files_imported", result)
    return result
