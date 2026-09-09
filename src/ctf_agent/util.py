from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import CTFError

SLUG_RE = re.compile(r"[^a-z0-9._-]+")
FLAG_PATTERNS = [
    re.compile(r"(?i)\bflag\{[^}\r\n]{1,256}\}"),
    re.compile(r"(?i)\bctf\{[^}\r\n]{1,256}\}"),
]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def slugify(value: str, fallback: str = "item") -> str:
    value = SLUG_RE.sub("-", value.strip().lower()).strip("-.")
    return value or fallback


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_yaml(path: Path) -> dict[str, Any]:
    import yaml

    if not path.is_file():
        raise CTFError(f"Missing YAML file: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CTFError(f"Invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise CTFError(f"Expected mapping in {path}")
    return data


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def atomic_write_yaml(path: Path, data: dict[str, Any]) -> None:
    import yaml

    atomic_write_text(path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def next_id(path: Path, prefix: str, width: int = 6) -> str:
    highest = 0
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d{{{width}}})$")
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            match = pattern.match(str(record.get("id", "")))
            if match:
                highest = max(highest, int(match.group(1)))
    return f"{prefix}-{highest + 1:0{width}d}"


def next_log_id(log_dir: Path) -> str:
    """Return the next LOG-* id for a challenge log directory.

    The id is derived from real on-disk metadata: the ``id`` field of existing
    ``*.json`` metadata wins, with the legacy ``NNNNNN-<tag>.json`` filename
    scheme as a fallback. Callers must hold the challenge runtime lock so the
    scan-then-allocate step is atomic across processes.
    """
    highest = 0
    if log_dir.is_dir():
        for path in log_dir.iterdir():
            if path.is_file():
                if path.suffix == ".json":
                    try:
                        record = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        record = None
                    if isinstance(record, dict):
                        match = re.match(r"^LOG-(\d{6})$", str(record.get("id", "")))
                        if match:
                            highest = max(highest, int(match.group(1)))
                match = re.match(r"^(\d{6})-", path.name)
                if match:
                    highest = max(highest, int(match.group(1)))
    return f"LOG-{highest + 1:06d}"


def detect_flag(text: str, pattern: str | None = None) -> str | None:
    if not pattern:
        for compiled in FLAG_PATTERNS:
            match = compiled.search(text)
            if match:
                return match.group(0)
        return None

    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise CTFError(f"Invalid flag pattern: {exc}") from exc
    match = regex.search(text)
    if not match:
        return None
    if regex.groups:
        return next((group for group in match.groups() if group is not None), None)
    return match.group(0)


def display_bytes(data: bytes, limit: int) -> str:
    if len(data) <= limit:
        return data.decode("utf-8", errors="replace")
    prefix = data[: limit // 2].decode("utf-8", errors="replace")
    suffix = data[-limit // 2 :].decode("utf-8", errors="replace")
    return f"{prefix}\n... [truncated {len(data) - limit} bytes] ...\n{suffix}"
