# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0] - 2026-09-09 (optimization batch 3: Phase 5)

### Added
- `logs/index.json` derived query index (log-id and command-hash lookups). Cache
  lookups no longer scan every metadata file; a missing/stale/corrupt index is
  rebuilt from canonical `logs/*.json`.
- Typed records (`src/ctf_agent/records.py`): `CommandMetadata`, `EvidenceRecord`,
  `AgentResult`, `LogIndexEntry` (functional TypedDicts, `total=False` for
  backward compatibility); `EvidenceLedger.add()` is annotated with `EvidenceRecord`.
- CLI split into per-domain command modules under `ctf_agent/commands/`
  (cli.py shrank from 793 to ~300 lines; parser + dispatch remain in `cli.py`).
- Regression/coverage tests: runner error paths, challenge selector/pointer edge
  cases, recon/ghidra adapters, CLI integration across all command groups.
- Coverage gate raised to the DoD target of 80% overall.

### Changed
- `run_command`/`run_tty` maintain `logs/index.json` incrementally.
- `context` rendering ignores `logs/index.json` (it is not a command record).

## [0.3.0] - 2026-09-09 (optimization batches 1-2)

### Added (batch 1: runtime/state/merge/security)

- Challenge-level runtime lock (`.runtime.lock`, `fcntl.flock` + in-process reentrancy) guarding state, log, evidence, flag, and merge mutations.
- State `revision` with compare-and-swap saves and a legal state-transition table; explicit `force` transitions require reason + evidence.
- Strict evidence-reference validation (`LOG-*`, `E-*`, artifacts) for facts, hypotheses, techniques, transitions, and merges.
- Specialist result schema v2 (`result_id`, `source_hash`), merge history (`reports/merged-results.jsonl`), idempotent re-merge and dedupe.
- Execution policy module (path containment, `original/` protection, budget projection interfaces) and redaction module (env/headers/inline secrets).
- Process-group execution with SIGTERM -> SIGKILL timeout escalation and scope `max_output_bytes` enforcement in the runner.
- Single-source version handling, ruff/mypy/pytest-cov quality gates (`make check`), CI workflow.
- Multi-process concurrency, security, and regression tests.

### Added (batch 2: scope limits enforcement + HTTP sessions)

- `.scope.yaml` usage ledger (`usage:` block) with atomic, lock-protected commit under the challenge runtime lock.
- Runtime enforcement of `request_rate_per_second`, `max_requests`, `max_scan_ports`, `max_runtime_minutes`, and `max_output_bytes`:
  - HTTP adapter commits one request per call; nmap adapter commits requested port counts; flag submission commits one request.
  - `run_command`/`run_tty` pre-check the runtime budget and commit wall-clock seconds after each execution.
- HTTP cookie sessions (`tool http --session ID`): cookies persist under `artifacts/http/sessions/<id>/cookies.json`; every request is recorded in `requests.jsonl` with redacted request/response headers, body hash/size, redirect chain, and timing; request bodies are stored for replay.
- `tool http-session show|replay ID` to inspect and replay a recorded session sequence.
- Redirect chains are recorded; every redirect hop remains scope-checked; stored logs never contain raw credentials (`Authorization`/`Cookie` values redacted).

### Changed

- `run_command`/`run_tty` hold the challenge lock for the full operation, run children in their own process group, and store redacted command metadata.
- CLI `--version` and `ctf_agent.__version__` read the version from `pyproject.toml`.
- Default scope limits updated (`request_rate_per_second: 1000`, `max_requests: 10000`, added `max_output_bytes`) and a `usage:` block is tracked.

## [0.2.0] - baseline

- Baseline commit: `baseline: ctf-agent v0.2.0, 26 tests passing`.
- Evidence-first AI CTF agent runtime for authorized challenges (existing feature set).
