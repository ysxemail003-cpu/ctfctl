"""Capability benchmark harness (Phase C of docs/CAPABILITY_PLAN.md).

The benchmark measures how well the *whole runtime* solves a self-contained,
original set of synthetic challenges. Each challenge is a directory with:

``challenge.json``      metadata (id/category/difficulty/flag/driver/...)
``original/``           immutable challenge inputs (imported into the run)
``support/``            helper inputs for the solver (e.g. wordlists)
``solve.py``            deterministic driver; prints ``FLAG=<value>`` on success

The harness:

- creates an isolated challenge workspace per run under ``bench/results/<date>/``;
- imports ``original/*`` through the normal ingest path (logged, hashed, 0444);
- starts a local target server for ``target: true`` challenges;
- executes the driver with a hard timeout;
- compares the reported flag to the expected one and writes
  ``summary.json`` / ``failure_modes.json`` / ``REPORT.md``.

Drivers that need an external tool declare it in ``requires``; when the tool is
missing the challenge is recorded as SKIPPED instead of FAILED, so the suite
still runs on minimal CI images.
"""
from __future__ import annotations

import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import solver as solver_module
from .adapters import ingest as ingest_adapter
from .challenge import init_challenge
from .errors import CTFError
from .util import utcnow

SUITE_SCHEMA_VERSION = 1
FLAG_MARKER = "FLAG="
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SUITE = REPO_ROOT / "bench" / "challenges"
DEFAULT_OUT = REPO_ROOT / "bench" / "results"
DEFAULT_CTFCTL = REPO_ROOT / "tools" / "ctfctl"


@dataclass
class BenchChallenge:
    """Parsed metadata for one synthetic challenge."""

    id: str
    category: str
    difficulty: str
    title: str
    description: str
    flag: str
    driver: str
    solve: str
    requires: list[str]
    target: bool
    root: Path
    files: list[str] = field(default_factory=list)


def discover_suite(suite_dir: Path) -> list[BenchChallenge]:
    """Recursively find every ``challenge.json`` under ``suite_dir`` (sorted)."""
    suite_dir = suite_dir.resolve()
    if not suite_dir.is_dir():
        raise CTFError(f"Benchmark suite not found: {suite_dir}")
    challenges: list[BenchChallenge] = []
    for manifest in sorted(suite_dir.rglob("challenge.json")):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CTFError(f"Invalid challenge manifest {manifest}: {exc}") from exc
        required = ("id", "category", "difficulty", "title", "flag")
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise CTFError(f"challenge.json {manifest} missing fields: {', '.join(missing)}")
        root = manifest.parent
        challenges.append(
            BenchChallenge(
                id=str(data["id"]),
                category=str(data["category"]),
                difficulty=str(data["difficulty"]),
                title=str(data["title"]),
                description=str(data.get("description", "")),
                flag=str(data["flag"]),
                driver=str(data.get("driver", "script")),
                solve=str(data.get("solve", "solve.py")),
                requires=[str(item) for item in data.get("requires", [])],
                target=bool(data.get("target", False)),
                root=root,
                files=[str(item) for item in data.get("files", [])],
            )
        )
    if not challenges:
        raise CTFError(f"No challenges found under {suite_dir}")
    return challenges


def _missing_requires(challenge: BenchChallenge) -> list[str]:
    return [tool for tool in challenge.requires if shutil.which(tool) is None]


class _BenchTargetHandler(http.server.BaseHTTPRequestHandler):
    """Serves the flag in a response header for web-style challenges."""

    flag = ""

    def do_GET(self):  # noqa: N802
        body = b"bench target"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Bench-Flag", self.flag)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: N802
        pass


def start_target_server(flag: str) -> tuple[str, int, Any]:
    """Start a local flag-header HTTP server on 127.0.0.1; returns (host, port, stop)."""
    _BenchTargetHandler.flag = flag
    server = socketserver.TCPServer(("127.0.0.1", 0), _BenchTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop() -> None:
        server.shutdown()
        server.server_close()

    return "127.0.0.1", int(server.server_address[1]), stop


def _parse_flag(output: str) -> str | None:
    for line in output.splitlines():
        if line.startswith(FLAG_MARKER):
            value = line[len(FLAG_MARKER):].strip()
            if value:
                return value
    return None


def _action_count(challenge_dir: Path) -> int:
    """Number of logged command records (metadata JSON files, excluding the index)."""
    log_dir = challenge_dir / "logs"
    if not log_dir.is_dir():
        return 0
    return len([p for p in log_dir.glob("*.json") if p.is_file() and p.name != "index.json"])


def run_challenge(
    challenge: BenchChallenge,
    out_dir: Path,
    ctfctl_path: Path = DEFAULT_CTFCTL,
    timeout: float = 180.0,
    python: str | None = None,
    driver: str | None = None,
    backend: Any = None,
    policy: Any = None,
    max_rounds: int = 8,
) -> dict[str, Any]:
    """Run one synthetic challenge and return its result record."""
    missing = _missing_requires(challenge)
    if missing:
        return {
            "id": challenge.id,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "status": "SKIPPED",
            "reason": f"missing tool(s): {', '.join(missing)}",
            "flag_matched": False,
            "duration_s": 0.0,
            "actions": 0,
            "run_dir": None,
        }

    stop_server = None
    target_url: str | None = None
    target_port: int | None = None
    if challenge.target:
        host, target_port, stop_server = start_target_server(challenge.flag)
        target_url = f"http://{host}:{target_port}/"

    workspace_root = out_dir / "work"
    workspace_root.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    run_dir: Path | None = None
    try:
        challenge_dir = init_challenge(
            workspace_root,
            "bench",
            challenge.id,
            challenge.category,
            "AI_NATIVE",
            target="127.0.0.1" if challenge.target else None,
            ports=[target_port] if target_port is not None else None,
            confirm_authorization=True,
        )
        run_dir = challenge_dir

        original_dir = challenge.root / "original"
        if original_dir.is_dir():
            sources = [p for p in sorted(original_dir.iterdir()) if p.is_file()]
            if sources:
                ingest_adapter.import_files(challenge_dir, sources, perform_recon=False)

        effective_driver = driver or challenge.driver
        if effective_driver == "solver":
            if policy is None and backend is None:
                return {
                    "id": challenge.id,
                    "category": challenge.category,
                    "difficulty": challenge.difficulty,
                    "title": challenge.title,
                    "status": "SKIPPED",
                    "reason": "solver driver requires a model backend (or a policy in tests)",
                    "flag_matched": False,
                    "duration_s": round(time.monotonic() - started, 3),
                    "actions": 0,
                    "rounds": 0,
                    "run_dir": str(challenge_dir.relative_to(out_dir)),
                }
            solve = solver_module.run_solve(
                challenge_dir,
                policy=policy,
                backend=backend,
                max_rounds=max_rounds,
                action_timeout=timeout,
                model_timeout=timeout,
                extra_context=f"Target URL: {target_url}" if target_url else None,
                ctfctl_path=ctfctl_path,
            )
            duration = round(time.monotonic() - started, 3)
            if solve.status == "SOLVED" and solve.flag == challenge.flag:
                status = "SOLVED"
                reason = solve.reason
                matched = True
            elif solve.status == "SOLVED":
                status = "FAILED"
                reason = f"flag mismatch: got {solve.flag!r}"
                matched = False
            else:
                status = "FAILED"
                reason = solve.reason or "unsolved"
                matched = False
            return {
                "id": challenge.id,
                "category": challenge.category,
                "difficulty": challenge.difficulty,
                "title": challenge.title,
                "status": status,
                "reason": reason,
                "flag_matched": matched,
                "duration_s": duration,
                "actions": _action_count(challenge_dir),
                "rounds": solve.rounds,
                "run_dir": str(challenge_dir.relative_to(out_dir)),
            }

        solve_script = challenge.root / challenge.solve
        if not solve_script.is_file():
            raise CTFError(f"solve driver missing: {solve_script}")

        command = [
            python or sys.executable,
            str(solve_script),
            "--challenge-dir",
            str(challenge_dir),
            "--root",
            str(challenge.root),
            "--ctfctl",
            str(ctfctl_path),
        ]
        if target_url:
            command += ["--target-url", target_url]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(challenge_dir),
            )
            rc = proc.returncode
            output = proc.stdout or ""
            error_tail = (proc.stderr or "")[-500:]
        except subprocess.TimeoutExpired as exc:
            rc = 124
            output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            error_tail = f"timed out after {timeout}s"

        duration = round(time.monotonic() - started, 3)
        reported = _parse_flag(output)
        matched = reported is not None and reported == challenge.flag
        if matched:
            status = "SOLVED"
            reason = None
        elif reported is not None:
            status = "FAILED"
            reason = f"flag mismatch: got {reported!r}"
        elif rc != 0:
            status = "ERROR"
            reason = f"driver exit {rc}: {error_tail.strip()[:300]}"
        else:
            status = "FAILED"
            reason = "driver produced no FLAG= line"

        return {
            "id": challenge.id,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "title": challenge.title,
            "status": status,
            "reason": reason,
            "flag_matched": matched,
            "duration_s": duration,
            "actions": _action_count(challenge_dir),
            "run_dir": str(challenge_dir.relative_to(out_dir)) if challenge_dir.is_relative_to(out_dir) else str(challenge_dir),
        }
    except Exception as exc:  # keep the suite alive on unexpected harness errors
        duration = round(time.monotonic() - started, 3)
        return {
            "id": challenge.id,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "title": challenge.title,
            "status": "ERROR",
            "reason": f"harness error: {type(exc).__name__}: {exc}",
            "flag_matched": False,
            "duration_s": duration,
            "actions": 0,
            "run_dir": str(run_dir) if run_dir else None,
        }
    finally:
        if stop_server is not None:
            stop_server()


def run_suite(
    suite_dir: Path = DEFAULT_SUITE,
    out_dir: Path | None = None,
    only: str | None = None,
    ctfctl_path: Path = DEFAULT_CTFCTL,
    timeout: float = 180.0,
    driver: str | None = None,
    backend: Any = None,
    policy: Any = None,
    max_rounds: int = 8,
) -> dict[str, Any]:
    """Run a whole benchmark suite and write summary/failure/report files."""
    suite_dir = Path(suite_dir).resolve()
    challenges = discover_suite(suite_dir)
    if only:
        challenges = [ch for ch in challenges if ch.id == only]
        if not challenges:
            raise CTFError(f"No challenge with id {only!r} in suite {suite_dir}")

    out_dir = Path(out_dir or DEFAULT_OUT).resolve()
    date_dir = out_dir / utcnow()[:10]
    run_dir = date_dir / f"run-{utcnow()[11:19].replace(':', '')}"
    run_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for challenge in challenges:
        result = run_challenge(
            challenge,
            run_dir,
            ctfctl_path=ctfctl_path,
            timeout=timeout,
            driver=driver,
            backend=backend,
            policy=policy,
            max_rounds=max_rounds,
        )
        results.append(result)

    summary: dict[str, Any] = {
        "schema_version": SUITE_SCHEMA_VERSION,
        "generated_at": utcnow(),
        "suite": str(suite_dir),
        "run_dir": str(run_dir),
        "ctfctl": str(ctfctl_path),
        "total": len(results),
        "counts": {status: sum(1 for r in results if r["status"] == status) for status in ("SOLVED", "FAILED", "ERROR", "SKIPPED")},
        "results": results,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    failure_modes: dict[str, Any] = {"counts": {}, "by_category": {}}
    for result in results:
        key = f"{result['status']}"
        if result["status"] in ("FAILED", "ERROR"):
            reason = result.get("reason") or ""
            key = f"{result['status']}:{reason.split(':')[0][:40]}"
        failure_modes["counts"][key] = failure_modes["counts"].get(key, 0) + 1
        cat = result["category"]
        failure_modes["by_category"].setdefault(cat, {}).setdefault(result["status"], 0)
        failure_modes["by_category"][cat][result["status"]] += 1
    (run_dir / "failure_modes.json").write_text(json.dumps(failure_modes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = ["# Benchmark Report", "", f"- Generated: {utcnow()}", f"- Suite: {suite_dir}", ""]
    lines += ["| id | category | difficulty | status | duration_s | actions |", "|---|---|---|---|---|---|"]
    for result in results:
        lines.append(
            f"| {result['id']} | {result['category']} | {result['difficulty']} | {result['status']} "
            f"| {result['duration_s']:.2f} | {result['actions']} |"
        )
    lines += ["", f"Totals: {summary['counts']}"]
    (run_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary
