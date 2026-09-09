# Benchmark Results

> Capability baseline for the self-contained synthetic suite
> (`bench/challenges/`, see `docs/CAPABILITY_PLAN.md` Phase C).
> Run artifacts are git-ignored (`bench/results/`); this file is the committed record.

## How to reproduce

```bash
make bench          # == ./tools/ctfctl bench
# single challenge:
./tools/ctfctl bench --only crypto/hash-crack
```

Artifacts land in `bench/results/<date>/run-<time>/`:
`summary.json` (full per-challenge records), `failure_modes.json`, `REPORT.md`,
plus each challenge's isolated workspace (`work/...`) with its own logs/evidence.

Live (LLM) solver baseline — run by the operator when a model CLI is available:

```bash
./tools/ctfctl bench --driver solver --backend auto
```

Results there include `rounds` per challenge. Record the outcome as the next
baseline row below.

## Baseline 1 — 2026-09-09 (v0.4.1 + Phase A adapters; suite v1: 6× easy)

Environment: Kali VM, Python 3.14, x86_64; john/hashid/binwalk/7z present.

| id | category | difficulty | status | duration_s | actions |
|---|---|---|---|---|---|
| hash-crack | crypto | easy | SOLVED | 0.72 | 4 |
| hidden-zip | forensics | easy | SOLVED | 3.71 | 3 |
| rot-multi | misc | easy | SOLVED | 0.08 | 1 |
| argv-gate | pwn | easy | SOLVED | 0.65 | 7 |
| xor-file | rev | easy | SOLVED | 0.08 | 1 |
| http-header | web | easy | SOLVED | 0.25 | 1 |

Totals: 6/6 SOLVED — 0 FAILED, 0 ERROR, 0 SKIPPED (suite wall time ≈ 6 s).

## Growth rules

- Every capability-phase change that touches solving must re-run `make bench`
  and update the newest baseline row; never delete older rows.
- A new challenge is required to keep CI/offline determinism: no external
  network, no real-competition material, and a `FLAG=`-printing `solve.py`.
- Suite v2 target: ≥2 challenges per category and at least one `medium`
  challenge per category (currently 6× easy, one per category).
