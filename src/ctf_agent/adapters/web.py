"""Structured web-audit adapters: ffuf fuzzing and read-only sqlmap automation.

Safety model (docs/CAPABILITY_PLAN.md Phase A3):

- Every run is scope-checked per URL (host + port) and usage-ledgered.
- ``ffuf`` requires an explicit wordlist and a ``FUZZ`` position; the number of
  requests is budgeted *before* execution so over-budget runs are refused.
- ``sqlmap`` is refused unless the caller supplies a resolvable evidence
  reference (LOG-*/E-*) showing manual evidence of injection, or passes
  ``force=True`` after an operator decision. Only conservative, read-only
  flags are ever emitted; destructive switches are never part of the builder.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..errors import CTFError
from ..evidence import validate_evidence_refs
from ..runner import run_command
from ..scope import ScopeStore
from ..util import next_log_id

_MC_SAFE = re.compile(r"^[0-9,\- ]+$")
_METHOD_SAFE = re.compile(r"^[A-Z]+$")
SQLMAP_MAX_LEVEL = 3
SQLMAP_MAX_RISK = 2


def _require_tool(name: str) -> None:
    if not shutil.which(name):
        raise CTFError(f"{name} is not installed or not in PATH.")


def _url_target(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise CTFError(f"Invalid http(s) URL: {url}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return str(parts.hostname).lower(), port


def _resolve_wordlist_path(challenge_dir: Path, wordlist: str) -> Path:
    path = Path(wordlist).expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    path = path.resolve()
    if not path.is_file():
        raise CTFError(f"Wordlist file not found: {wordlist}")
    return path


def _wordlist_lines(path: Path) -> int:
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def ffuf_scan(
    challenge_dir: Path,
    url: str,
    wordlist: str,
    method: str = "GET",
    data: str | None = None,
    match_codes: str = "200,204,301,302,307,401,403",
    rate: int = 50,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Run a scoped ffuf fuzz against one URL with an explicit wordlist.

    The URL (or ``data`` for POST parameter fuzzing) must contain a ``FUZZ``
    keyword. Requests are budgeted against ``.scope.yaml`` limits before
    ffuf starts; over-budget runs raise before a single request is sent.
    """
    challenge_dir = challenge_dir.resolve()
    _require_tool("ffuf")
    if "FUZZ" not in url and "FUZZ" not in (data or ""):
        raise CTFError("ffuf requires a FUZZ keyword in the URL (or --data) to substitute wordlist entries.")
    if not _MC_SAFE.match(match_codes):
        raise CTFError("--match-codes must be a comma/dash separated list of HTTP codes.")
    if not _METHOD_SAFE.match(method):
        raise CTFError(f"Invalid HTTP method: {method}")
    if rate < 1 or rate > 5000:
        raise CTFError("--rate must be between 1 and 5000 requests/second.")

    wordlist_path = _resolve_wordlist_path(challenge_dir, wordlist)
    requests = max(1, _wordlist_lines(wordlist_path)) * max(1, url.count("FUZZ") + (data or "").count("FUZZ"))

    host, port = _url_target(url)
    scope = ScopeStore(challenge_dir)
    scope.check(host, port)
    # Budget before execution: refuse over-budget fuzz runs up front.
    scope.commit_usage({"requests": requests})

    log_dir = challenge_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_id = next_log_id(log_dir)
    sequence = log_id.split("-")[1]
    out_dir = challenge_dir / "artifacts" / "ffuf"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"{sequence}-ffuf.json"

    argv = ["ffuf", "-u", url, "-w", str(wordlist_path), "-mc", match_codes, "-rate", str(rate)]
    if method != "GET":
        argv += ["-X", method]
    if data:
        argv += ["-d", data]
    argv += ["-o", str(out_json), "-of", "json"]

    metadata = run_command(
        challenge_dir,
        argv,
        f"ffuf-{sequence}",
        "web-recon",
        network=True,
        target=host,
        port=port,
        timeout=timeout,
        quiet=True,
    )

    hits: list[dict[str, Any]] = []
    if out_json.is_file():
        try:
            payload = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            payload = {}
        for item in payload.get("results", [])[:200]:
            hits.append(
                {
                    "word": (item.get("input") or {}).get("FUZZ"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "url": item.get("url"),
                    "redirect": item.get("redirectlocation"),
                }
            )

    return {
        "schema_version": 1,
        "tool": "ffuf",
        "target": url,
        "method": method,
        "wordlist": str(wordlist_path),
        "requests_budgeted": requests,
        "hit_count": len(hits),
        "hits": hits,
        "artifacts": {"json": str(out_json.relative_to(challenge_dir))},
        "logs": {"ffuf": metadata["id"]},
    }


def build_sqlmap_argv(
    url: str,
    level: int = 1,
    risk: int = 1,
    output_dir: str = ".",
    technique: str | None = None,
) -> list[str]:
    """Build a conservative, read-only sqlmap command line.

    Kept as a pure function so the safety invariants are unit-testable without
    launching sqlmap: only batch/quiet informational flags are emitted; no
    file-read, OS-shell, takeover, or out-of-band flags can be requested.
    """
    level = max(1, min(int(level), SQLMAP_MAX_LEVEL))
    risk = max(1, min(int(risk), SQLMAP_MAX_RISK))
    argv = [
        "sqlmap",
        "-u",
        url,
        "--batch",
        "--disable-coloring",
        "--level",
        str(level),
        "--risk",
        str(risk),
        "--crawl=0",
        "--threads",
        "1",
        "--output-dir",
        output_dir,
    ]
    if technique:
        cleaned = re.sub(r"[^A-Z]", "", technique.upper())[:10]
        if cleaned:
            argv += ["--technique", cleaned]
    return argv


def sqlmap_audit(
    challenge_dir: Path,
    url: str,
    evidence_ref: str | None = None,
    level: int = 1,
    risk: int = 1,
    timeout: float = 600.0,
    force: bool = False,
) -> dict[str, Any]:
    """Run read-only sqlmap against one URL, gated on manual evidence.

    sqlmap is slow and noisy by nature; the adapter returns a compact summary:
    a boolean ``detected_vulnerable`` plus matching excerpt lines. The full
    sqlmap transcript remains in the LOG stdout file for review.
    """
    challenge_dir = challenge_dir.resolve()
    _require_tool("sqlmap")
    if not force:
        if not evidence_ref:
            raise CTFError(
                "sqlmap requires manual evidence of injection first: pass --evidence LOG-*/E-* "
                "(or --force after an explicit operator decision)."
            )
        validate_evidence_refs(challenge_dir, [evidence_ref])
    host, port = _url_target(url)
    ScopeStore(challenge_dir).check(host, port)

    log_dir = challenge_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_id = next_log_id(log_dir)
    sequence = log_id.split("-")[1]
    out_dir = challenge_dir / "artifacts" / "sqlmap" / sequence
    out_dir.mkdir(parents=True, exist_ok=True)

    argv = build_sqlmap_argv(url, level=level, risk=risk, output_dir=str(out_dir))
    metadata = run_command(
        challenge_dir,
        argv,
        f"sqlmap-{sequence}",
        "web-audit",
        network=True,
        target=host,
        port=port,
        timeout=timeout,
        quiet=True,
    )

    stdout_path = challenge_dir / str(metadata.get("stdout_file", ""))
    excerpt: list[str] = []
    vulnerable = False
    if stdout_path.is_file():
        text = stdout_path.read_text(encoding="utf-8", errors="replace")
        markers = ("is vulnerable", "parameter", "back-end dbms", "current database", "payload")
        for line in text.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in markers):
                excerpt.append(line.strip()[:220])
                if "is vulnerable" in lowered:
                    vulnerable = True
        excerpt = excerpt[-40:]

    return {
        "schema_version": 1,
        "tool": "sqlmap",
        "target": url,
        "level": max(1, min(int(level), SQLMAP_MAX_LEVEL)),
        "risk": max(1, min(int(risk), SQLMAP_MAX_RISK)),
        "detected_vulnerable": vulnerable,
        "excerpt": excerpt,
        "artifacts": {"output_dir": str(out_dir.relative_to(challenge_dir))},
        "logs": {"sqlmap": metadata["id"]},
    }
