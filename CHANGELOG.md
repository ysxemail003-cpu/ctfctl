# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - capability phase (Batch 1a: Phase A1/A2 tool adapters)

### Added
- Crypto adapters (`ctf_agent/adapters/crypto.py`): `ctfctl tool hashid` (offline shape heuristic +
  `hashid` enrichment with MD5-over-MD2 style preference), `ctfctl tool crack` (local john/hashcat
  cracking; wordlist required; hash argv validated against injection; artifacts under `work/hashes/`).
- Forensics adapters (`ctf_agent/adapters/forensics.py`): `ctfctl tool exif`, `binwalk`
  (scan; `--extract` lands in `work/extracted/`), `archive` (7z listing), `zsteg` (tool crashes
  reported as `status=error`, not a hard failure), `pcap` (capinfos + tshark protocol hierarchy).
- `ctfctl doctor` now reports hashid/john/hashcat/exiftool/binwalk/7z/unzip/zsteg/tshark/capinfos.
- Adapter coverage table in `docs/TOOL_ROUTING.md`.

### Changed
- None (additive CLI/subcommands only; existing commands unchanged).

### Tested
- 21 new adapter tests (hash shape, argument safety, hashid parsing, john cracked/not-cracked,
  exif, binwalk scan/extract, 7z listing/rejection, zsteg clean/error, pcap summary). hashcat
  end-to-end is opt-in via `CTF_TEST_HASHCAT=1` (slow OpenCL startup).



### Added
- Task leases (`ctf_agent/tasks.py`, Phase 3 Task C): `start_task` /
  `heartbeat` / `take_over` / `release_task` stored in `state.yaml#active_tasks`
  with `lease_until`; live leases cannot be taken over; every change is an event.
- Evidence-safe log archival (`ctf_agent/logarchive.py`): `logs summary` and
  `logs archive [--dry-run]` CLI; only logs unreferenced by state, evidence,
  flags, and events are moved to `logs/archive/<date>/`; the query index is
  rebuilt after archiving.
- Projection de-duplication: `STATE.md`/`EVIDENCE.md` renders skip rewriting
  when the generated content is unchanged (`util.write_if_changed`).
- Coverage regressions: task leases, log archival, runner non-quiet/cache-skip
  output, ELF missing/relative/non-ELF recon, render-skip.

### Changed
- `default_state()` now seeds `active_tasks: []` (additive schema v1 key).

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
