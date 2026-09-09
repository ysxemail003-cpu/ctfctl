"""Structured crypto adapters: hash identification and local password cracking.

Design constraints (see docs/CAPABILITY_PLAN.md Phase A1):

- Cracking operates on local files only (no remote hashcat/john services).
- Destructive or expensive actions require explicit arguments; reading is default.
- Every command goes through ``runner.run_command`` so it is logged, hashed,
  scoped, budgeted, and capped, exactly like the other tool adapters.
- Hash values passed on argv are validated to a safe character set to avoid
  argument injection into the underlying CLI.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from typing import Any

from ..errors import CTFError
from ..runner import run_command

# Printable, whitespace-free characters that appear in hashes / password
# markers (e.g. ``$2b$12$...`` bcrypt, ``user:hash`` for john files).
_HASH_SAFE = re.compile(r"^[A-Za-z0-9+/=:.$*_\-]{1,512}$")
_HASHID_LINE = re.compile(r"^\[\+\]\s+(.+?)\s*$")
_HASHCAT_MODE = re.compile(r"Hashcat Mode:\s*(\d+)")
_JOHN_FORMAT = re.compile(r"JtR Format:\s*([^\]]+)")
_PLAIN_LINE = re.compile(r"^([^:]*):([^:]+)$")

# Shape detection for common raw hashes, used both as a fast offline answer
# and to pick defaults when hashid/john/hashcat are unavailable.
_SHAPE_TABLE: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$"), "bcrypt", "bcrypt"),
    (re.compile(r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{86}$"), "sha512crypt", "sha512crypt"),
    (re.compile(r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{43}$"), "sha256crypt", "sha256crypt"),
    (re.compile(r"^[0-9a-fA-F]{64}$"), "sha256-hex", "raw-sha256"),
    (re.compile(r"^[0-9a-fA-F]{56}$"), "sha224-hex", "raw-sha224"),
    (re.compile(r"^[0-9a-fA-F]{40}$"), "sha1-hex", "raw-sha1"),
    (re.compile(r"^[0-9a-fA-F]{32}$"), "md5-hex", "raw-md5"),
    (re.compile(r"^[0-9a-fA-F]{16}$"), "mysql323-hex", "mysql323"),
    (re.compile(r"^[0-9a-fA-F]{128}$"), "sha512-hex", "raw-sha512"),
]


def _require_tool(name: str) -> None:
    if not shutil.which(name):
        raise CTFError(f"{name} is not installed or not in PATH.")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", value)[:80] or "hash"


def _stdout(challenge_dir: Path, metadata: dict[str, Any]) -> str:
    path = challenge_dir / str(metadata.get("stdout_file", ""))
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def classify_hash_shape(value: str) -> dict[str, Any]:
    """Offline shape classification; never requires an external tool."""
    for pattern, family, john_format in _SHAPE_TABLE:
        if pattern.match(value):
            return {
                "family": family,
                "shape": "hex" if "-hex" in family else "crypt",
                "suggested_john_format": john_format,
                "suggested_hashcat_mode": 0 if family == "md5-hex" else None,
            }
    return {"family": "unknown", "shape": "unknown", "suggested_john_format": None, "suggested_hashcat_mode": None}


def _parse_hashid(text: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _HASHID_LINE.match(line.strip())
        if not match:
            continue
        body = match.group(1).strip()
        name = body.split(" [")[0].strip()
        mode_match = _HASHCAT_MODE.search(body)
        fmt_match = _JOHN_FORMAT.search(body)
        candidates.append(
            {
                "name": name,
                "hashcat_mode": int(mode_match.group(1)) if mode_match else None,
                "john_format": fmt_match.group(1).strip() if fmt_match else None,
            }
        )
    return candidates


def identify_hash(challenge_dir: Path, value: str, timeout: float = 30.0) -> dict[str, Any]:
    """Identify a hash with the local shape heuristic, enriched by ``hashid`` when installed."""
    challenge_dir = challenge_dir.resolve()
    value = (value or "").strip()
    if not value:
        raise CTFError("A hash value is required.")
    if not _HASH_SAFE.match(value):
        raise CTFError("Hash value contains unsafe characters; refusing to pass it to a CLI.")

    result: dict[str, Any] = {
        "schema_version": 1,
        "tool": "hashid",
        "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        "length": len(value),
        "shape": classify_hash_shape(value),
        "candidates": [],
        "suggested": None,
        "logs": {},
    }
    if not shutil.which("hashid"):
        result["note"] = "hashid not installed; shape heuristic only."
        return result

    metadata = run_command(
        challenge_dir,
        ["hashid", "-m", "-j", value],
        f"hashid-{_safe_name(value)}",
        "crypto-recon",
        timeout=timeout,
        quiet=True,
    )
    candidates = _parse_hashid(_stdout(challenge_dir, metadata))
    result["candidates"] = candidates
    result["logs"]["hashid"] = metadata["id"]
    result["suggested"] = _suggest_candidate(candidates, result["shape"].get("family", ""))
    return result


def _suggest_candidate(candidates: list[dict[str, Any]], family: str) -> dict[str, Any] | None:
    """Pick the most probable candidate: prefer one matching the shape family,
    then the first candidate that carries a john/hashcat mode."""
    keyword = family.split("-")[0] if family and family != "unknown" else ""
    scorable = [c for c in candidates if c.get("john_format") or c.get("hashcat_mode") is not None]
    if not scorable:
        return None
    if keyword:
        for item in scorable:
            if keyword in item["name"].lower():
                return {
                    "name": item["name"],
                    "hashcat_mode": item["hashcat_mode"],
                    "john_format": item["john_format"],
                }
    first = scorable[0]
    return {
        "name": first["name"],
        "hashcat_mode": first["hashcat_mode"],
        "john_format": first["john_format"],
    }


def _resolve_input_path(challenge_dir: Path, path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    path = path.resolve()
    if not path.is_file():
        raise CTFError(f"Input file not found: {path}")
    return path


def _write_hash_file(challenge_dir: Path, value: str, tag: str) -> Path:
    hashes_dir = challenge_dir / "work" / "hashes"
    hashes_dir.mkdir(parents=True, exist_ok=True)
    target = hashes_dir / f"{tag}.txt"
    if not target.is_file() or target.read_text(encoding="utf-8", errors="replace").strip() != value:
        target.write_text(value + "\n", encoding="utf-8")
    return target


def _john_format(value: str, format_hint: str | None) -> str | None:
    if format_hint:
        return format_hint
    return classify_hash_shape(value).get("suggested_john_format")


def _crack_with_john(
    challenge_dir: Path,
    hash_path: Path,
    wordlist: Path,
    fmt: str | None,
    timeout: float,
    pot_file: Path,
) -> tuple[str, list[str], dict[str, Any], dict[str, Any]]:
    args = ["john", f"--pot={pot_file}", f"--wordlist={wordlist}"]
    if fmt:
        args.append(f"--format={fmt}")
    args.append(str(hash_path))
    run_meta = run_command(
        challenge_dir,
        args,
        f"john-{hash_path.stem}",
        "crypto-crack",
        timeout=timeout,
        quiet=True,
    )
    show_args = ["john", "--show", f"--pot={pot_file}"]
    if fmt:
        show_args.append(f"--format={fmt}")
    show_args.append(str(hash_path))
    show_meta = run_command(
        challenge_dir,
        show_args,
        f"john-show-{hash_path.stem}",
        "crypto-crack",
        timeout=timeout,
        quiet=True,
    )
    plaintexts: list[str] = []
    for line in _stdout(challenge_dir, show_meta).splitlines():
        match = _PLAIN_LINE.match(line.strip())
        if match and match.group(2):
            plaintexts.append(match.group(2))
    status = "cracked" if plaintexts else "not_cracked"
    return status, plaintexts, run_meta, show_meta


def _crack_with_hashcat(
    challenge_dir: Path,
    hash_path: Path,
    wordlist: Path,
    mode: int,
    timeout: float,
) -> tuple[str, list[str], dict[str, Any], dict[str, Any] | None]:
    pot_file = challenge_dir / "work" / "hashes" / f"{hash_path.stem}.hashcat.pot"
    out_file = challenge_dir / "work" / "hashes" / f"{hash_path.stem}.hashcat.out"
    run_meta = run_command(
        challenge_dir,
        [
            "hashcat",
            "-m",
            str(mode),
            "-a",
            "0",
            "--potfile-path",
            str(pot_file),
            "-o",
            str(out_file),
            "--quiet",
            str(hash_path),
            str(wordlist),
        ],
        f"hashcat-{hash_path.stem}",
        "crypto-crack",
        timeout=timeout,
        quiet=True,
    )
    plaintexts: list[str] = []
    if out_file.is_file():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                plaintexts.append(line.split(":", 1)[1])
    status = "cracked" if plaintexts else "not_cracked"
    return status, plaintexts, run_meta, None


def crack_hash(
    challenge_dir: Path,
    value: str | None = None,
    hash_file: Path | None = None,
    wordlist: Path | None = None,
    tool: str = "john",
    timeout: float = 600.0,
    format_hint: str | None = None,
    mode: int | None = None,
) -> dict[str, Any]:
    """Crack a local hash with john or hashcat.

    Exactly one of ``value`` (hash string) or ``hash_file`` (a john-style file)
    must be given. ``wordlist`` is mandatory: the adapter never downloads or
    guesses dictionaries. ``tool='john'`` is the default; hashcat requires an
    explicit or inferable ``mode`` (hashcat mode number).
    """
    challenge_dir = challenge_dir.resolve()
    if (value is None) == (hash_file is None):
        raise CTFError("Provide exactly one of value or --hash-file.")
    if wordlist is None:
        raise CTFError("A wordlist is required for cracking (refusing to guess dictionaries).")
    wordlist = _resolve_input_path(challenge_dir, wordlist)
    if tool not in ("john", "hashcat"):
        raise CTFError(f"Unsupported crack tool: {tool}")

    if value is not None:
        value = value.strip()
        if not _HASH_SAFE.match(value):
            raise CTFError("Hash value contains unsafe characters.")
        hash_path = _write_hash_file(challenge_dir, value, _safe_name(value)[:40])
    else:
        hash_path = _resolve_input_path(challenge_dir, hash_file or Path(""))
        copied = challenge_dir / "work" / "hashes" / f"{hash_path.stem}.txt"
        copied.parent.mkdir(parents=True, exist_ok=True)
        if not copied.is_file():
            import shutil as _sh

            _sh.copy2(hash_path, copied)
        hash_path = copied

    sample = value if value is not None else hash_path.read_text(encoding="utf-8", errors="replace").strip()
    run_meta: dict[str, Any]
    show_meta: dict[str, Any] | None
    if tool == "john":
        _require_tool("john")
        fmt = _john_format(sample, format_hint)
        pot_file = challenge_dir / "work" / "hashes" / f"{hash_path.stem}.john.pot"
        status, plaintexts, run_meta, show_meta = _crack_with_john(
            challenge_dir, hash_path, wordlist, fmt, timeout, pot_file
        )
    else:
        _require_tool("hashcat")
        resolved_mode = mode
        if resolved_mode is None:
            resolved_mode = classify_hash_shape(sample).get("suggested_hashcat_mode")
        if resolved_mode is None:
            raise CTFError("hashcat requires --mode (could not infer a hashcat mode for this hash).")
        status, plaintexts, run_meta, show_meta = _crack_with_hashcat(
            challenge_dir, hash_path, wordlist, int(resolved_mode), timeout
        )

    result: dict[str, Any] = {
        "schema_version": 1,
        "tool": tool,
        "status": status,
        "plaintexts": plaintexts,
        "wordlist": str(wordlist),
        "logs": {"crack": run_meta["id"]},
        "artifacts": {"hash_file": str(hash_path.relative_to(challenge_dir))},
    }
    if show_meta:
        result["logs"]["show"] = show_meta["id"]
    return result
