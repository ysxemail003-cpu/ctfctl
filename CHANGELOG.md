# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - capability phase (Batch 1g: Phase D platform bridge + trajectory)

### Added
- Platform bridge (`ctf_agent/platform.py` + `ctfctl platform ctfd list|pull`): `NormalizedChallenge`
  abstraction and a minimal CTFd v1 JSON client over stdlib urllib (no new deps). Token read from
  environment only (never written to disk); attachment downloads are host-locked (no SSRF);
  `pull` creates AI_NATIVE workspaces with a persistent `no_auto_submit` constraint and imports
  attachments via the normal ingest path. Submission stays behind existing `flag submit` gates.
- Trajectory export (`ctf_agent/trajectory.py` + `ctfctl trajectory export`): aggregates logged
  actions, evidence ledger, agent rounds and flag record into a CSAW-style machine-readable
  `reports/trajectory-<name>.json` plus a Markdown sidecar. Only already-redacted stored data is used.
- Tests: mock-CTFd integration (list/detail/download/submit, cross-host refusal, workspace pull +
  idempotency) and trajectory aggregation (actions/evidence/rounds/flag, persisted outputs).



### Added
- 6 new original medium challenges (one per category), giving every category an easy + medium:
  crypto/repeat-xor (known-prefix key recovery), forensics/dns-exfil (pcap DNS query),
  web/login-flag (GET hint -> POST /login, local target server login mode), pwn/bof-win
  (stack overflow with offset search), rev/data-xor (XOR blob inside ELF), misc/layered
  (gzip > zip > ROT13).
- Benchmark target server gains a `login` mode (`server`/`server_creds` manifest fields):
  GET / returns a hint, POST /login with valid creds returns the flag header.
- `bench/RESULTS.md` baseline 2: 12/12 SOLVED in ≈ 9 s.

### Changed
- crypto/rsa-tiny removed during development: a message longer than the tiny modulus is not
  recoverable, so the design was replaced with repeating-key XOR (see baseline history).



### Added
- `ctfctl bench --driver solver --backend auto` runs each challenge through the solve-loop
  engine (Phase B) instead of the bundled `solve.py`; per-challenge results add `rounds` and map
  SOLVED/STUCK to bench SOLVED/FAILED; unsupported model CLIs fail fast at CLI start.
- Missing backend/policy inside the harness yields SKIPPED (harness-tolerant for tests).
- `solver.run_solve`/`compose_round_prompt` accept `extra_context` (used to inject the local
  target URL for web challenges into every round prompt).



### Added
- Model backends (`ctf_agent/backends.py`): uniform `complete(prompt)` over codex (`codex exec -o`),
  claude (`claude -p`), gemini (`gemini -p`); PATH detection, clear missing-CLI errors, `auto`
  preference order; no live model calls in tests.
- Solve-loop engine (`ctf_agent/solver.py` + `ctfctl solve`): PLAN-less round loop
  (round = prompt -> policy JSON action -> execute `ctfctl run|tool` actions -> record), with
  static per-category playbook injection (skill injection), round recording under
  `<challenge>/agent_rounds/round-<NN>/` (prompt.md/response.json/record.json), flag detection in
  action output or model `flag_candidate`, canonical flag-candidate recording, and stop conditions:
  solved flag, policy `conclusion: stuck`, two idle rounds without new evidence, or `max_rounds`.
- Policies: `ScriptedPolicy` (deterministic tests/replays) and `BackendPolicy` (strict JSON action
  object parsing with one tolerated bad reply).

### Tested
- 17 backend/solver tests (argv builders, availability errors, JSON extraction, solved via output
  flag, solved via candidate, stuck on idle/conclusion/invalid replies, event + flag-candidate
  recording). `make check`: ruff/mypy clean.



### Added
- Capability benchmark harness (`ctf_agent/bench.py` + `ctfctl bench`): discovers
  `challenge.json` manifests, creates an isolated AI_NATIVE workspace per run, imports
  `original/*` through the normal ingest path, starts a local target server for web-style
  challenges, executes a deterministic `solve.py` driver under timeout, and writes
  `summary.json` / `failure_modes.json` / `REPORT.md` under `bench/results/<date>/`.
- Missing required tools are reported as SKIPPED (not FAILED) so the suite can run on
  minimal CI images; drivers report via a `FLAG=` line; per-challenge `actions` counts
  logged command records.
- Synthetic suite v1 (`bench/challenges/`): 6 original easy challenges, one per category —
  crypto/hash-crack (john), forensics/hidden-zip (binwalk carve), web/http-header (local
  target server), pwn/argv-gate (strings + run), rev/xor-file, misc/rot-multi.
- `make bench` target; `bench/RESULTS.md` baseline 1 (6/6 SOLVED ≈ 6 s).



### Added
- Web adapters (`ctf_agent/adapters/web.py`): `ctfctl tool ffuf` (scope-checked, FUZZ-position
  required, wordlist mandatory, request budget committed *before* execution so over-budget runs
  are refused) and `ctfctl tool sqlmap` (read-only argv builder with hard caps level≤3/risk≤2 and
  no destructive flags; execution requires a resolvable `--evidence` reference unless `--force`).
- Pwn/rev helpers (`ctf_agent/adapters/pwn.py`): `ctfctl tool rop` (structured ROPgadget gadgets,
  `--only`/`--depth`/`--max-gadgets`) and `ctfctl tool imports` (readelf `--dyn-syms` UND imports).
- 16 new adapter + CLI tests (sqlmap argv invariants, ffuf validation/scope/end-to-end on a local
  HTTP server, ROP/imports parsing, evidence-gate behavior).

### Tested
- `make check`: ruff/mypy clean; overall coverage >= 80%; adapter modules >= 80%.



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
