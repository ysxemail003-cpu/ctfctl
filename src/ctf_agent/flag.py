from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .errors import FlagError, StateError
from .runner import run_command
from .scope import ScopeStore
from .state import StateStore
from .util import append_jsonl, atomic_write_yaml, detect_flag, next_id, next_log_id, utcnow

TEXT_SUFFIXES = {
    ".txt",
    ".md",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".html",
    ".htm",
    ".xml",
    ".csv",
    ".log",
    ".stdout",
    ".stderr",
    ".transcript",
    "",
}
MAX_SCAN_SIZE = 20 * 1024 * 1024


def _iter_text_files(root: Path) -> list[Path]:
    result: list[Path] = []
    for base in ("logs", "artifacts", "work", "original"):
        directory = root / base
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES and path.stat().st_size <= MAX_SCAN_SIZE:
                result.append(path)
    return sorted(result)


def detect(challenge_dir: Path, pattern: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for path in _iter_text_files(challenge_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        value = detect_flag(text, pattern)
        if value:
            key = (str(path.relative_to(challenge_dir)), value)
            if key not in seen:
                seen.add(key)
                matches.append({"file": key[0], "value": value})
        if len(matches) >= limit:
            break
    return matches


def candidate(
    challenge_dir: Path,
    value: str,
    source: str,
    command: str | None = None,
    pattern: str | None = None,
) -> dict[str, Any]:
    state = StateStore(challenge_dir)
    record = {
        "id": next_id(challenge_dir / "flags" / "candidates.jsonl", "FLAG"),
        "value": value,
        "status": "CANDIDATE",
        "source": source,
        "command": command,
        "pattern": pattern,
        "timestamp": utcnow(),
    }
    append_jsonl(challenge_dir / "flags" / "candidates.jsonl", record)
    state.update_flag(
        {
            "status": "CANDIDATE",
            "value": value,
            "pattern": pattern,
            "source": [source],
        },
        "flag_candidate",
    )
    return record


def verify_replay(
    challenge_dir: Path,
    replay: str,
    runs: int = 2,
    expected: str | None = None,
    pattern: str | None = None,
    timeout: float | None = None,
    network: bool = False,
    target: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    if runs < 1:
        raise FlagError("Runs must be >= 1")
    if runs == 1:
        raise FlagError("At least 2 runs are required for automatic reproduction; use 2 or more.")
    command = shlex.split(replay)
    if not command:
        raise FlagError("Empty replay command")
    state = StateStore(challenge_dir)
    observed: list[str | None] = []
    logs: list[str] = []
    for index in range(1, runs + 1):
        metadata = run_command(
            challenge_dir,
            command,
            tag=f"flag-replay-{index}",
            classification="flag-verification",
            force=True,
            quiet=True,
            timeout=timeout,
            network=network,
            target=target,
            port=port,
        )
        logs.append(metadata["id"])
        stdout_path = challenge_dir / metadata["stdout_file"]
        output = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.is_file() else ""
        found = detect_flag(output, pattern)
        observed.append(found or output.strip() or None)

    if expected is not None:
        valid = all(value == expected for value in observed)
        final_value: str | None = expected
    else:
        non_null = [value for value in observed if value is not None]
        valid = bool(non_null) and len(set(non_null)) == 1 and len(non_null) == len(observed)
        final_value = non_null[0] if valid else None

    if not valid:
        result = {
            "verified": False,
            "runs": runs,
            "observed": observed,
            "logs": logs,
            "reason": "outputs did not match, no flag detected, or expected value missing",
        }
        state.update_flag(
            {
                "status": "CANDIDATE",
                "reproduction": {
                    "verified": False,
                    "runs": runs,
                    "values_match": False,
                    "last_log": logs[-1] if logs else None,
                },
            },
            "flag_verification_failed",
        )
        raise FlagError(json.dumps(result, ensure_ascii=False, indent=2))

    assert final_value is not None
    flag_record = {
        "status": "REPRODUCED",
        "value": final_value,
        "pattern": pattern,
        "source": logs,
        "reproduction": {
            "verified": True,
            "runs": runs,
            "values_match": True,
            "last_log": logs[-1],
        },
        "timestamp": utcnow(),
    }
    atomic_write_yaml(challenge_dir / "flags" / "flag.yaml", flag_record)
    state.update_flag(
        {
            "status": "REPRODUCED",
            "value": final_value,
            "pattern": pattern,
            "source": logs,
            "reproduction": {
                "verified": True,
                "runs": runs,
                "values_match": True,
                "last_log": logs[-1],
            },
        },
        "flag_reproduced",
    )
    state.set_next(
        "Decide whether to submit the reproduced flag",
        objective="Complete flag verification",
    )
    if state.load().get("status") != "SOLVED":
        reason = "Candidate flag reproduced at least twice"
        try:
            state.transition("VERIFICATION", reason, logs)
        except StateError:
            # Direct verification after reproduction may skip intermediate
            # statuses; record the override as a forced, evidenced transition.
            state.transition(
                "VERIFICATION",
                f"{reason} (forced: direct verification after reproduction)",
                logs,
                force=True,
            )
    return {
        "verified": True,
        "value": final_value,
        "runs": runs,
        "logs": logs,
    }


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent an authenticated submission from following a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def submit(
    challenge_dir: Path,
    url: str,
    token_env: str,
    challenge_id: int,
    value: str | None = None,
    yes: bool = False,
    timeout: float = 20.0,
) -> dict[str, Any]:
    state_store = StateStore(challenge_dir)
    state = state_store.load()
    scope_store = ScopeStore(challenge_dir)
    scope = scope_store.load()
    value = value or state.get("flag", {}).get("value")
    if not value:
        raise FlagError("No flag value supplied and state has no candidate flag.")

    dry_run = not yes
    plan = {
        "url": url,
        "challenge_id": challenge_id,
        "value": value,
        "dry_run": dry_run,
        "requirements": [
            "operator approval",
            "no no_auto_submit constraint",
            "allow_flag_submission in .scope.yaml",
            "confirmed authorization",
            "flag status REPRODUCED",
            "submission platform URL inside .scope.yaml",
        ],
    }
    if dry_run:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return {"dry_run": True, **plan}

    if "no_auto_submit" in state.get("operator_constraints", []):
        raise FlagError(
            "Operator constraint `no_auto_submit` is active. Ask for explicit approval, "
            "then run `ctfctl state constraint remove no_auto_submit` before submitting."
        )
    if not scope.get("authorization", {}).get("rules", {}).get("allow_flag_submission", False):
        raise FlagError("Flag submission is not enabled in .scope.yaml. Run `ctfctl scope allow flag-submission` first.")
    if not scope.get("authorization", {}).get("confirmed", False):
        raise FlagError("Authorization is not confirmed in .scope.yaml.")
    if state.get("flag", {}).get("status") != "REPRODUCED":
        raise FlagError("Flag must be reproduced at least twice before submission.")

    parsed_url = urlsplit(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise FlagError("Submission URL must be a full http:// or https:// URL.")
    scope_result = scope_store.check(url)
    state_data = state_store.load()
    state_data.setdefault("scope", {})["checked_at"] = scope_result["checked_at"]
    state_store.save(state_data)

    token = os.environ.get(token_env)
    if not token:
        raise FlagError(f"Missing submission token in environment variable {token_env}")
    payload = json.dumps({"challenge_id": challenge_id, "submission": value}).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Token {token}",
            "User-Agent": "ctf-agent/0.2",
        },
        method="POST",
    )
    opener = build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            status_code = response.status
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        status_code = exc.code
    except URLError as exc:
        raise FlagError(f"Submission request failed: {exc}") from exc

    accepted = False
    try:
        parsed = json.loads(body)
        data = parsed.get("data") if isinstance(parsed, dict) else {}
        accepted = status_code in range(200, 300) and (
            (isinstance(data, dict) and str(data.get("status", "")).lower() in {"correct", "accepted"})
            or parsed.get("success") is True
        )
    except json.JSONDecodeError:
        parsed = {"raw": body}

    log_dir = challenge_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_id = next_log_id(log_dir)
    sequence = log_id.split("-")[1]
    log_path = log_dir / f"{sequence}-flag-submit.json"
    log_path.write_text(
        json.dumps(
            {
                "id": log_id,
                "type": "flag_submission",
                "url": url,
                "status_code": status_code,
                "accepted": accepted,
                "response": parsed,
                "timestamp": utcnow(),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    state_store.update_flag(
        {
            "status": "ACCEPTED" if accepted else "REJECTED",
            "submission": {
                "submitted": True,
                "accepted": accepted,
                "platform": url,
                "accepted_at": utcnow() if accepted else None,
            },
        },
        "flag_submission_result",
    )
    if accepted:
        accepted_path = challenge_dir / "flags" / "accepted.txt"
        accepted_path.write_text(value + "\n", encoding="utf-8")
        os.chmod(accepted_path, 0o600)
        state_store.transition("SOLVED", "Platform accepted the flag", [log_id])
    if not accepted:
        raise FlagError(f"Platform did not accept the flag. HTTP {status_code}: {body[:1000]}")
    return {"accepted": True, "status_code": status_code, "log": log_id, "response": parsed}
