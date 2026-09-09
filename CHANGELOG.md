# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - Phase G (knowledge ledger + review)

### Added

- Cross-challenge knowledge ledger (`ctf_agent/knowledge.py` + `ctfctl knowledge add|list|propose|review|stats`):
  evidence-backed entries by category/technique/trigger/outcome stored in
  `workspace/knowledge.jsonl`. Entries never store flags/answers (rejected on add and
  scan-guarded in stats); every entry requires resolvable LOG-*/E-* references.
- `ctfctl knowledge propose` scans recorded challenge techniques and proposes entries
  (operator commits them; nothing is auto-written).
- `ctfctl knowledge review` writes `reports/review-<name>.md` per challenge (timeline,
  techniques, waste points).
- Solve-loop prompts now inject matching knowledge (`successful` first) so agents stop
  repeating failed techniques; ledger contains no flag-like content by construction.



### Summary

- **Phase A** — structured Kali-tool adapters: crypto (hashid + john/hashcat crack),
  forensics (exif / binwalk / archive / zsteg / pcap), web (ffuf + evidence-gated sqlmap),
  pwn/rev (ROPgadget / readelf imports).
- **Phase B** — autonomous solve loop (`ctfctl solve`) with per-category playbooks, round
  recording under `agent_rounds/`, strict JSON action contract, and model backends
  (codex / claude / gemini).
- **Phase C** — capability benchmark (`ctfctl bench`): 12-challenge offline synthetic suite
  (every category easy + medium), script and solver drivers, metrics, committed baselines.
- **Phase D** — platform bridge (`ctfctl platform ctfd list|pull`, token from env, host-locked
  downloads, `no_auto_submit` workspaces) and trajectory export (`ctfctl trajectory export`,
  CSAW-style JSON + Markdown).
- **Phase E** — parallel racing (`ctfctl race`, first SOLVED wins), `ctfctl bench --parallel N`,
  and a rewritten runtime lock that is safe for concurrent threads and processes.
- **Open-source prep** — MIT license, bilingual README, CONTRIBUTING / SECURITY, `make demo`,
  git-history secret scan.

### Batch notes

#### Batch 1a (Phase A1/A2) — crypto + forensics adapters

- `ctfctl tool hashid` (offline shape heuristic + hashid enrichment with shape-aware
  suggestion) and `ctfctl tool crack` (local john/hashcat, wordlist required, argv validation).
- `ctfctl tool exif | binwalk | archive | zsteg | pcap` with read-only defaults; binwalk
  extraction lands in `work/extracted/`; zsteg crashes reported as `status=error`.
- `doctor` reports the new tool set; adapter coverage table in `docs/TOOL_ROUTING.md`.

#### Batch 1b (Phase A3/A4) — web + pwn/rev adapters

- `ctfctl tool ffuf` (FUZZ position required, request budget committed before execution) and
  `ctfctl tool sqlmap` (read-only argv builder, evidence gate unless `--force`).
- `ctfctl tool rop` (structured ROPgadget) and `ctfctl tool imports` (readelf dyn-syms).

#### Batch 1c (Phase C v1) — benchmark harness

- `ctfctl bench`: manifest discovery, isolated AI_NATIVE workspaces, ingest of original/,
  local target server for web challenges, deterministic `FLAG=` drivers, missing-tool SKIPPED.
- First 6-challenge suite and `bench/RESULTS.md` baseline 1 (6/6 SOLVED ~6s).

#### Batch 1d (Phase B skeleton) — solve loop + backends

- `ctfctl solve` round loop, `agent_rounds/`, ScriptedPolicy + BackendPolicy, flag detection
  and canonical flag-candidate recording, stop conditions (solved / stuck / idle / max rounds).

#### Batch 1e (Phase B/C integration) — bench solver driver

- `ctfctl bench --driver solver --backend auto` runs the solve-loop engine per challenge;
  `solver.run_solve` gained `extra_context` (web target URL injection).

#### Batch 1f (Phase C v2) — suite expansion

- 6 new original medium challenges (one per category); target server `login` mode;
  `bench/RESULTS.md` baseline 2 (12/12 SOLVED ~9s). crypto/rsa-tiny removed during dev
  (plaintext longer than modulus is unrecoverable) and replaced with repeating-key XOR.

#### Batch 1g (Phase D) — platform bridge + trajectory

- CTFd v1 client over stdlib urllib, host-locked attachment downloads, pull semantics;
  trajectory aggregation (actions / evidence / agent rounds / flag).

#### Batch 1h (Phase E) — parallel racing + lock safety

- `ctfctl race`, independent per-backend rounds, first SOLVED wins, others cancelled.
- `ctfctl bench --parallel N`.
- runtime lock rewritten: owner-thread + polling model, fd closed on release so forked
  children never share an open file description (concurrent threads and processes both safe).

## [0.4.1] - 2026-09-09 (optimization batch 4)

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
