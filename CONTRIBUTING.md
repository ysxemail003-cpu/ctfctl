# Contributing

Thanks for helping. ctf-agent is an evidence-first runtime for **authorized**
CTF/lab work, and those rules shape every contribution.

## Ground rules

- Only work against targets you are authorized to test. No real-competition
  flags, answers, or credentials in this repository — including tests, docs,
  and synthetic benchmark material (`bench/` challenges are all original).
- `state.yaml` is canonical; `STATE.md`/`EVIDENCE.md` are generated — never
  edit them by hand or use them as test fixtures.
- Every important claim in code/docs should be reproducible; code changes need
  tests; solving changes need a `make bench` result recorded in
  `bench/RESULTS.md`.

## Where things live

| Area | Location |
|---|---|
| Process layer (runner/state/scope/evidence/flag/lock) | `src/ctf_agent/` (v0.4.1 contract in `docs/ARCHITECTURE.md`) |
| Capability layer (solver/backends/bench/platform/trajectory) | `src/ctf_agent/` (`docs/SOLVER_ARCHITECTURE.md`) |
| Engineering contract & phased plan | `docs/CAPABILITY_PLAN.md` |
| Synthetic benchmark suite | `bench/challenges/` |
| Agent specs (Claude/Codex) | `agent-specs/`, synced via `ctfctl sync-agents` |

## Development loop

```bash
make dev            # create .venv with dev deps
make check          # tests + ruff + mypy + coverage (gate: >=80%)
make bench          # synthetic capability benchmark (script driver)
make scan-secrets   # scan git history for high-signal secret patterns
```

Per-domain commands: `make test`, `make lint`, `make typecheck`,
`make coverage`, `make demo`.

## Before you open a PR

1. Read the relevant phase and acceptance criteria in `docs/CAPABILITY_PLAN.md`;
   respect the file-ownership table (no cross-scope edits).
2. Add regression tests for every behavior change; keep fixtures real
   (generate logs/evidence through the runtime, never fake `LOG-*` refs).
3. Run `make check` locally and paste the summary in the PR description.
4. If the change touches solving, run `make bench` and add/update a row in
   `bench/RESULTS.md`.
5. Fill the delivery checklist from the plan (§10): completed items, changed
   files, compatibility impact, new tests, test results, open issues, rollback.

## Style

- Python >= 3.11; ruff (E4/E7/E9/F/W, line length 120) and mypy clean.
- No new runtime dependencies without discussion (the runtime is stdlib +
  PyYAML; tools are invoked via adapters).
- New CLI surface must be documented in `README.md` and covered by a CLI test.

## Reporting bugs

Open an issue with a minimal reproduction. For security findings, see
`SECURITY.md` instead of filing a public issue.
