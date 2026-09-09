# ctf-agent — Evidence-First AI CTF Runtime

A lightweight, auditable runtime for authorized CTF and lab work on Kali Linux. It gives Claude Code and Codex a shared contract for challenge directories, command logging, durable state, specialist handoffs, and flag verification.

> Use only on systems and challenges you are explicitly authorized to test. Event rules always override this repository.

## Install

Kali blocks system-wide `pip` installs by default. Use the bundled launcher directly:

```bash
cd ~/ctf-agent
./tools/ctfctl --help
```

Optional editable install in a local virtual environment:

```bash
cd ~/ctf-agent
make install
source .venv/bin/activate
ctfctl --help
```

## Conversational usage

The intended interface is natural language. You should not need to memorize `ctfctl`.

In Claude Code or Codex, from `~/ctf-agent`, say:

```text
帮我解这道 Web 题：
比赛 2026-demo，题目 web-login，
目标 http://challenge.example.ctf，
比赛允许 AI 自动解题，
不要自动提交 flag，
附件 ~/Downloads/web.zip。
```

Then say:

```text
继续
```

or:

```text
当前状态
```

The agent internally uses `ctfctl intake`, `ctfctl context`, `ctfctl tool`, `ctfctl run`, state updates, specialist handoffs, and flag verification. Routine commands are hidden from the operator.

Useful operator phrases:

- `继续` — resume the current challenge from its saved next action.
- `当前状态` — show facts, hypotheses, failures, flag status, and next action.
- `为什么？` — explain a conclusion with `LOG-*` / `E-*` evidence.
- `换个方向` — abandon the current hypothesis and choose another.
- `不要提交 flag` — require an explicit decision before submission.
- `生成报告` — create `reports/final.md`.

## Quick start

```bash
cd ~/ctf-agent
./tools/ctfctl doctor

./tools/ctfctl init \
  --event 2026-demo \
  --challenge web-login \
  --category web \
  --mode AI_NATIVE \
  --target challenge.example.ctf \
  --port 80 \
  --confirm-authorization

export CTF_CHALLENGE_DIR="$PWD/workspace/contests/2026-demo/web-login"

./tools/ctfctl state show
./tools/ctfctl tool http http://challenge.example.ctf/
./tools/ctfctl flag verify --replay 'python3 scripts/solve.py' --runs 2
```

## Core rules

1. `state.yaml` is canonical; `STATE.md` is generated.
2. `original/` is immutable; use `work/`.
3. Every substantive command goes through `ctfctl run` or `ctfctl tool`.
4. Network commands require `--network --target`; add `--port` when the target itself has no port and the scope lists specific ports.
5. Every fact and hypothesis references `LOG-*`, `E-*`, or an artifact.
6. A flag is not solved until reproduced, and not accepted until the platform says so.

## Commands

### Environment

```bash
./tools/ctfctl doctor
```

### Challenge

```bash
./tools/ctfctl init ...
./tools/ctfctl state show
./tools/ctfctl state render
./tools/ctfctl report final ...
```

### Scope

```bash
./tools/ctfctl scope show
./tools/ctfctl scope confirm --notes "..."
./tools/ctfctl scope add-host example.ctf --port 80
./tools/ctfctl scope check example.ctf 80
./tools/ctfctl scope allow flag-submission
```

### Conversational runtime

```bash
./tools/ctfctl intake --text '...'
./tools/ctfctl import-files ~/Downloads/chall.zip
./tools/ctfctl current
./tools/ctfctl challenges
./tools/ctfctl use EVENT/CHALLENGE
./tools/ctfctl status --markdown
./tools/ctfctl context --markdown
```

### Commands and tools

```bash
./tools/ctfctl run --tag strings -- strings original/chall
./tools/ctfctl tool file original/chall
./tools/ctfctl tool web-inventory http://example.ctf/
./tools/ctfctl tool nmap example.ctf --port 80 --port 443
./tools/ctfctl run --tag nmap --network --target example.ctf -- nmap -Pn -sV -p 80 example.ctf
./tools/ctfctl run --tag remote --network --target pwn.example.ctf --port 1337 -- python3 scripts/exploit.py
./tools/ctfctl tty --tag gdb -- gdb work/chall
./tools/ctfctl tool http http://example.ctf/
./tools/ctfctl tool elf original/chall
./tools/ctfctl tool ghidra original/chall
```

### State and evidence

```bash
./tools/ctfctl state fact add "..." --evidence LOG-000001
./tools/ctfctl state hypothesis add "..." --test "..." --expected "..."
./tools/ctfctl state hypothesis update H-0001 --status CONFIRMED --result "..."
./tools/ctfctl state technique "..." failed --evidence LOG-000002
./tools/ctfctl state next "..."
./tools/ctfctl evidence add --source LOG-000001 --observation "..." --meaning "..."
```

### Agents

```bash
./tools/ctfctl handoff ctf-agent-web \
  --objective "Map HTTP routes" \
  --input state.yaml \
  --constraint "Stay in scope"

./tools/ctfctl merge-result reports/result-web.json
```

### Flags

```bash
./tools/ctfctl flag detect
./tools/ctfctl flag candidate --value 'flag{...}' --source LOG-000101
./tools/ctfctl flag verify --replay 'python3 scripts/solve.py' --runs 2
./tools/ctfctl flag submit --url https://ctfd.example/api/v1/flags --challenge-id 12
```

Submission is dry-run by default. Add `--yes` only when event rules and `.scope.yaml` explicitly allow automatic submission. A persistent `no_auto_submit` constraint blocks submission until the operator explicitly approves removing it.

## Claude Code and Codex

Generate project agent files:

```bash
./tools/ctfctl sync-agents
```

Install Codex skills into `~/.codex/skills`:

```bash
./tools/ctfctl sync-agents --install-codex
```

Claude Code reads `CLAUDE.md`, which is a symlink to `AGENTS.md`. Specialist definitions are under `.claude/agents/`. Codex uses the root `AGENTS.md` and skills generated under `.codex/skills/`.

## Optimization roadmap

The implementation plan for runtime hardening, concurrency safety, evidence validation,
execution policy, specialist merge idempotency, HTTP sessions, and future performance
work is maintained in [`docs/OPTIMIZATION_PLAN.md`](docs/OPTIMIZATION_PLAN.md).

The document is an implementation contract for delegated AI developers. It defines
work ownership, non-goals, acceptance criteria, security constraints, test matrix,
and the required delivery format.

## Development

```bash
make test
```

## Design goals

- **Capability:** specialist agents, structured tool adapters, and Ghidra/Pwntools-friendly workflows.
- **Efficiency:** command caching, compact state, structured summaries, and deliberate escalation.
- **Auditability:** command metadata, stdout/stderr, hashes, evidence ledger, and event history.
- **Safety:** authorization mode, explicit target scope, dry-run submission, and stop-and-ask rules.
