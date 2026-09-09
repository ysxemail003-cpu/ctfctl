# Changelog

All notable changes are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased] - first optimization batch

### Added
- Challenge-level runtime lock (`.runtime.lock`, `fcntl.flock` + in-process reentrancy) guarding state, log, evidence, flag, and merge mutations.
- State `revision` with compare-and-swap saves and a legal state-transition table; explicit `force` transitions require reason + evidence.
- Strict evidence-reference validation (`LOG-*`, `E-*`, artifacts) for facts, hypotheses, techniques, transitions, and merges.
- Specialist result schema v2 (`result_id`, `source_hash`), merge history (`reports/merged-results.jsonl`), idempotent re-merge and dedupe.
- Execution policy module (path containment, `original/` protection, budget projection interfaces) and redaction module (env/headers/inline secrets).
- Process-group execution with SIGTERM -> SIGKILL timeout escalation and scope `max_output_bytes` enforcement in the runner.
- Multi-process concurrency, security, and regression tests (53 passing total).
- Single-source version handling, ruff/mypy/pytest-cov quality gates (`make check`), and a CI workflow.

### Changed
- `run_command`/`run_tty` now hold the challenge lock for the full operation and run children in their own process group.
- CLI `--version` and `ctf_agent.__version__` read the version from `pyproject.toml`.

## [0.2.0] - baseline

- Baseline commit: `baseline: ctf-agent v0.2.0, 26 tests passing`.
- Evidence-first AI CTF agent runtime for authorized challenges (existing feature set).
- Added single-source version handling, Makefile quality gates (`test`, `lint`, `typecheck`, `coverage`, `check`, `build`), and CI workflow.
