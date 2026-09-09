# Solver Architecture — the capability layer

> This document describes the **capability layer** added in the deep-optimization
> phase (see `docs/CAPABILITY_PLAN.md`). The evidence/scope/concurrency **process
> layer** (v0.2–v0.4.1) is documented in `docs/ARCHITECTURE.md` and is unchanged.

The project is two layers on top of each other:

```text
┌─ Capability layer (this doc): solve loop, model backends, benchmark,     ┐
│   platform bridge, trajectory export, racing                            │
├──────────────────────────────────────────────────────────────────────────┤
│   only calls public ctfctl primitives (run/tool/state/evidence/flag)    │
├──────────────────────────────────────────────────────────────────────────┤
└─ Process layer: runner (lock/timeout/redaction/budget), state (CAS),    ┘
     scope, evidence, flag lifecycle, merge idempotency, logs index
```

The invariant: **capability code never mutates canonical state directly** — every
action is executed through `ctfctl` so it is logged, scoped, budgeted and
evidence-linked by the normal runtime.

## Module map

| Module | Responsibility |
|---|---|
| `solver.py` | Round loop, policies, stop conditions, race orchestration |
| `backends.py` | Model CLI abstraction (`codex`/`claude`/`gemini`) |
| `bench.py` | Synthetic-suite benchmark (script or solver driver, parallel) |
| `platform.py` | CTF platform bridge (CTFd v1 client, `NormalizedChallenge`) |
| `trajectory.py` | CSAW-style trajectory export (JSON + Markdown) |
| `commands/{solve,bench,platform,trajectory}_cmd.py` | CLI handlers |

## The solve loop (`ctfctl solve`)

One round = **compose prompt → policy returns a JSON action → engine executes
the proposed `ctfctl` commands → outcome is recorded** → repeat.

Per-round prompt contains: state digest (facts/hypotheses/next action), file
inventory (original/work), the per-category playbook, previous rounds, and any
operator/bench extra context (e.g. a web target URL).

Policy JSON contract:

```json
{
  "analysis": "what I learned and why the next action makes sense",
  "commands": [["run", "--tag", "x", "--", "python3", "work/x.py"],
               ["tool", "file", "work/in"]],
  "flag_candidate": "flag{...} | null",
  "conclusion": "stuck | null"
}
```

Only `run` and `tool` action roots are accepted; tokens are length-capped. Every
executed action returns its LOG ids; flag detection scans outputs and the model
candidate. Stop conditions: solved flag, `conclusion: stuck`, two consecutive
rounds with no new evidence, or `max_rounds`.

Round artifacts land in:

```text
<challenge>/agent_rounds/
├── round-01/prompt.md        # what the policy saw
├── round-01/response.json    # raw policy output
├── round-01/record.json      # executed actions, log ids, candidate
├── round-02/...
└── summary.json
```

Policies: `ScriptedPolicy` (deterministic tests/replays) and `BackendPolicy`
(strict JSON parsing with one tolerated bad reply).

## Model backends (`backends.py`)

A backend is a thin CLI wrapper returning the model's final text:

- `codex` → `codex exec -o <file> <prompt>` (final message to file)
- `claude` → `claude -p <prompt>`
- `gemini` → `gemini -p <prompt>` (same convention)

Availability is probed per call; a missing CLI raises a clear error instead of
failing mid-solve. `ctfctl solve --backend auto` picks the first installed one.

## Racing (`ctfctl race`)

Multiple backends attack one challenge concurrently; the first SOLVED wins.

- Each worker keeps an independent round namespace: `agent_rounds/<backend>/`.
- Workers are threads; actions from different workers serialize on the
  challenge runtime lock (which is thread- and process-safe, see below).
- When a worker reaches SOLVED it signals a shared stop event; the others
  cancel between rounds and record `CANCELLED`.
- `agent_rounds/race-summary.json` records per-backend status/rounds/flag and
  the winner.

Racing is off by default; `--backends codex,claude` opts in.

### Runtime lock notes (why racing is safe)

`runtime_lock.py` keeps one cached file descriptor per challenge path, tracks
the owning thread, and takes the OS `flock` for the owning thread only. The fd
is closed on full release so a `fork()`ed child never shares an open file
description (which would silently defeat cross-process `flock`). This makes the
lock safe for concurrent **threads** and **processes** on the same challenge.

## Benchmark (`make bench` / `ctfctl bench`)

The suite lives in `bench/challenges/<category>/<id>/` and is fully offline and
deterministic. Each challenge has:

```text
challenge.json   # id/category/difficulty/flag/driver/requires/server...
original/        # immutable inputs (imported into the run workspace)
support/         # extra solver inputs (wordlists, ...)
solve.py         # deterministic driver; prints FLAG=<flag>
```

Drivers:
- `--driver script` (default): run the bundled `solve.py` (CI-safe).
- `--driver solver --backend auto`: run the solve-loop engine (needs a model CLI).

Per-run metrics go to `bench/results/<date>/run-<time>/`:
`summary.json`, `failure_modes.json`, `REPORT.md`, plus each challenge's
isolated workspace with its own logs/evidence. Missing required tools are
reported as SKIPPED, not FAILED. `--parallel N` runs challenges concurrently.
Committed baselines live in `bench/RESULTS.md`.

For web challenges the harness starts a local target server (`header` mode or
`login` mode with `server_creds` from the manifest), so HTTP flows are tested
without external network.

## Platform bridge (`ctfctl platform ctfd`)

- `list`: GET `/api/v1/challenges`.
- `pull --event NAME`: list → detail → create an `AI_NATIVE` workspace with a
  persistent `no_auto_submit` constraint → download attachments (host-locked,
  no SSRF) → import them through the normal ingest path. Idempotent.
- Token comes from the environment (`CTFD_TOKEN` by default); never written to
  disk. Submission stays behind the existing `ctfctl flag submit` gates
  (dry-run/`--yes`/scope/constraint).

## Trajectory export (`ctfctl trajectory export`)

Aggregates logged actions, the evidence ledger, agent rounds and the flag
record into `reports/trajectory-<name>.json` (machine-readable, CSAW-style:
thoughts / actions / observations / final flag) plus a Markdown sidecar. Only
already-redacted stored data is used; secrets are never re-printed.

## Invariants and extension points

1. Capability code only calls public primitives; never edits `state.yaml`,
   `logs/`, `evidence.jsonl` internals directly.
2. Anything that produces a flag must end in the canonical `flag.candidate →
   verify → submit` lifecycle (racing/bench drivers only record candidates).
3. New tools belong behind adapters only when structured parsing beats raw
   stdout (see `docs/TOOL_ROUTING.md` coverage table).
4. New model CLIs are added by implementing the `Backend` protocol and
   registering the binary in `backends.available_backends()`.
5. New platforms implement the `Platform` protocol (list/detail/download/
   submit) and are wired in `commands/platform_cmd.py`.
6. Every behavior change ships with a regression test; solving changes must
   re-run `make bench`.
