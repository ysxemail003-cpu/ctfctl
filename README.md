[**English**](README.md) | [**简体中文**](README.zh-CN.md)

# ctfctl

**Evidence-first, agentic CTF runtime for Kali Linux** — build, run, and audit your own AI CTF experts.

> Use only on systems and challenges you are explicitly authorized to test. Event rules always override this repository.

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python >= 3.11](https://img.shields.io/badge/python-3.11+-3776AB.svg)
![Target: Kali Linux](https://img.shields.io/badge/target-Kali%20Linux-557C94.svg)

---

## What it is

`ctfctl` is a runtime that turns natural language into an **auditable CTF-solving workflow**.
Instead of a one-shot prompt pack, it gives you (or your team) a layered system for fielding
**your own AI CTF experts**: structured access to Kali tools, an autonomous solve loop, a
reproducible capability benchmark, a CTF-platform bridge, and CSAW-style trajectory export —
with every step logged, scope-checked and evidence-linked.

It is **not**:

- a permission bypass — authorization, scope, and event rules are enforced in code;
- a single hard-coded solver — it is a runtime you build agents on;
- a black box — every claim resolves back to a `LOG-*` / `E-*` artifact.

## Highlights

- **Evidence is enforced, not suggested.** Facts, hypotheses, and state transitions must
  reference real logs or artifacts; unresolved references are rejected.
- **State survives context.** `state.yaml` is canonical; compression, restarts, and model
  switches never lose progress (`ctfctl context`, `next_action`).
- **Safety is code, not a prompt.** Target scope, per-hop redirect checks, secret redaction,
  process-group timeouts, budget ledgers, and dry-run flag submission.
- **It actually solves.** Structured adapters for crypto/forensics/web/pwn/rev tools, an
  autonomous solve loop (`ctfctl solve`), parallel racing (`ctfctl race`), and a
  12-challenge offline benchmark (`ctfctl bench`) that measures progress.
- **It ships for competitions.** CTFd `pull`, `no_auto_submit` by default, and trajectory
  export aligned with agentic-CTF submission requirements.

## Capability map

| Area | Status | Where |
|---|---|---|
| Process layer: lock / state / evidence / scope / flags / logs | shipped (v0.4.1) | `docs/ARCHITECTURE.md` |
| Structured Kali-tool adapters (crypto, forensics, web, pwn/rev) | shipped | `docs/TOOL_ROUTING.md` |
| Solve loop + model backends (codex / claude / gemini) | shipped | `docs/SOLVER_ARCHITECTURE.md` |
| Benchmark: 12 original challenges (6× easy + 6× medium) | shipped, 12/12 script baseline | `bench/RESULTS.md` |
| CTFd platform bridge + trajectory export | shipped | `docs/SOLVER_ARCHITECTURE.md` |
| Parallel racing + thread/process-safe runtime lock | shipped | `docs/SOLVER_ARCHITECTURE.md` |
| Memory / knowledge ledger, harder suite v3 | next | `docs/CAPABILITY_PLAN.md` |

## Quick start

```bash
cd ~/ctfctl
./tools/ctfctl doctor                     # environment + tool availability

./tools/ctfctl init \
  --event 2026-demo --challenge web-login --category web \
  --mode AI_NATIVE --target challenge.example.ctf --port 80 \
  --confirm-authorization

export CTF_CHALLENGE_DIR="$PWD/workspace/contests/2026-demo/web-login"
./tools/ctfctl state show
./tools/ctfctl tool web-inventory http://challenge.example.ctf/
```

Daily-driver commands:

```bash
./tools/ctfctl tool hashid <hash>                    # identify a hash
./tools/ctfctl tool crack <hash> --wordlist words.txt --tool john
./tools/ctfctl tool exif|binwalk|archive|zsteg|pcap <file>
./tools/ctfctl tool ffuf http://host/FUZZ --wordlist words.txt
./tools/ctfctl tool rop binary --only 'pop|ret'      # pwn/rev recon
./tools/ctfctl solve --backend auto                  # autonomous solve loop
./tools/ctfctl race --backends codex,claude          # race backends; first SOLVED wins
./tools/ctfctl bench                                 # offline capability benchmark
./tools/ctfctl platform ctfd pull --url https://ctf.example --event EVENT
./tools/ctfctl trajectory export                     # CSAW-style trajectory JSON + MD
```

`make demo` runs a complete no-model walkthrough: doctor → init → hashid/john →
evidence → trajectory export → benchmark subset.

## How it works

```text
operator / orchestrator
  → intake / context                  (natural language in, state out)
  → scope + authorization             (no scope, no action)
  → run / tool / tty                  (every command logged + budgeted)
  → logs / evidence / state           (the audit trail)
  → solve loop / specialists          (hypothesis-driven rounds)
  → flag candidate → verify → submit  (gated, dry-run by default)
  → report / trajectory               (human + machine readable)
```

Two layers with one rule: **capability code only calls public runtime primitives; it never
mutates canonical state directly.** Every solve-loop action executes through `ctfctl`, so the
evidence layer stays intact even when agents race in parallel.

Repository layout:

```text
src/ctf_agent/          process + capability layer (import name: ctf_agent)
bench/challenges/       original offline synthetic challenges (no real-competition material)
agent-specs/            orchestrator / web / pwn / rev / verification specs
examples/demo.sh        end-to-end demo
docs/                   architecture, plans, tool routing, solver architecture
```

## Development

```bash
make dev             # create .venv with dev dependencies
make check           # tests + ruff + mypy + coverage (gate >= 80%)
make bench           # capability benchmark (script driver)
make demo            # end-to-end demo
make scan-secrets    # scan git history for high-signal secret patterns
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution workflow and
[`SECURITY.md`](SECURITY.md) for responsible disclosure. This project is licensed under the
[MIT License](LICENSE).

## Documents

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — process layer (v0.4.1 contract)
- [`docs/SOLVER_ARCHITECTURE.md`](docs/SOLVER_ARCHITECTURE.md) — capability layer
- [`docs/TOOL_ROUTING.md`](docs/TOOL_ROUTING.md) — Kali tool routing + adapter coverage
- [`docs/CAPABILITY_PLAN.md`](docs/CAPABILITY_PLAN.md) — engineering roadmap & status
- [`docs/OPENSOURCE_REVIEW.md`](docs/OPENSOURCE_REVIEW.md) — third-party positioning review
- [`CHANGELOG.md`](CHANGELOG.md)
