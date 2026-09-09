# AGENTS.md — AI CTF Agent Runtime Contract

This project is an evidence-first agent runtime for **authorized CTF, lab, and cyber-range work only**. It is not a permission bypass. If authorization, target scope, or contest AI rules are unclear, stop and ask the operator.

## 1. Conversational front door

The operator is not required to learn `ctfctl`. Natural language is the user interface; the agent translates it into safe runtime actions.

- New challenge → `ctfctl intake`
- Resume → `ctfctl current` + `ctfctl context --markdown`
- Switch → `ctfctl use EVENT/CHALLENGE`
- Status → `ctfctl status --markdown`

Ask only for blocking missing facts such as authorization, target scope, input file, or submission policy. Do not ask the operator to choose routine commands. Continue autonomously only inside the authorized mode and `.scope.yaml`. Report compact evidence-backed checkpoints rather than raw shell noise.

## 2. Non-negotiable principles

1. **Authorization first.** Read `.scope.yaml` before any active operation.
2. **Evidence first.** No important claim without `LOG-*`, `E-*`, or an artifact.
3. **State is durable.** Read `state.yaml`; do not rely on conversation memory.
4. **Minimal action.** Use the smallest command that answers the next question.
5. **No fake success.** A flag is solved only after reproduction and, when required, platform acceptance.
6. **No unsafe target expansion.** Never attack hosts, ports, or services absent from `.scope.yaml`.
7. **Original inputs are immutable.** Analyze copies in `work/`, not files in `original/`.

Classify statements explicitly:

- `FACT`: directly supported by a command, file, response, or debugger result.
- `INFERENCE`: derived from facts but not directly observed.
- `HYPOTHESIS`: possible explanation requiring a test.
- `UNKNOWN`: insufficient evidence.

## 3. Runtime layout

The reusable framework is this repository. Concrete challenges live below:

```text
workspace/contests/<event>/<challenge>/
├── .scope.yaml
├── state.yaml
├── STATE.md
├── EVIDENCE.md
├── events.jsonl
├── evidence.jsonl
├── original/
├── work/
├── artifacts/
├── scripts/
├── logs/
├── reports/
└── flags/
```

`state.yaml` is canonical. `STATE.md` and `EVIDENCE.md` are generated. Do not edit them manually.

## 4. Startup sequence

For a new challenge:

```bash
cd ~/ctf-agent
./tools/ctfctl doctor
./tools/ctfctl init \
  --event EVENT \
  --challenge NAME \
  --category CATEGORY \
  --mode AI_NATIVE \
  --target HOST_OR_URL \
  --port 80 \
  --confirm-authorization
```

Then edit `.scope.yaml` only through `ctfctl scope` commands. Add every target before touching it.

To resume an existing challenge:

```bash
cd ~/ctf-agent
./tools/ctfctl state show
./tools/ctfctl state render
```

Or set:

```bash
export CTF_CHALLENGE_DIR=~/ctf-agent/workspace/contests/EVENT/NAME
```

## 5. Authorization and scope

Before active work, confirm all of these:

1. The challenge is authorized.
2. AI usage is allowed by the event rules.
3. The AI mode is `HUMAN_ONLY`, `AI_ASSISTED`, or `AI_NATIVE`.
4. Targets and ports are present in `.scope.yaml`.
5. Automated scanning, exploitation, external search, and flag submission are explicitly enabled when needed.

Useful commands:

```bash
./tools/ctfctl scope show
./tools/ctfctl scope confirm --notes "Operator confirmed event rules"
./tools/ctfctl scope add-host example.ctf --port 80 --port 443
./tools/ctfctl scope check http://example.ctf/
./tools/ctfctl scope allow flag-submission
```

In `HUMAN_ONLY` mode, do not perform active challenge work. In `AI_ASSISTED` mode, explain and analyze, but do not replace the human solver unless the operator explicitly requests permitted assistance.

## 6. Command discipline

All substantive commands must use `ctfctl run` or `ctfctl tool`:

```bash
./tools/ctfctl run --tag strings -- strings original/chall
./tools/ctfctl run --tag nmap-http --network --target example.ctf -- nmap -Pn -sV -p 80,443 example.ctf
./tools/ctfctl run --tag remote-exploit --network --target pwn.example.ctf --port 1337 -- python3 scripts/exploit.py
./tools/ctfctl tool http http://example.ctf/
./tools/ctfctl tool elf original/chall
./tools/ctfctl tool ghidra original/chall
```

Network tools must include `--network --target`. If the target does not contain a port and the scope lists specific ports, also pass `--port`. Do not run `curl`, `nmap`, `ffuf`, `gobuster`, `nc`, `sqlmap`, or equivalent directly.

Use `ctfctl tty` for GDB or other interactive tools:

```bash
./tools/ctfctl tty --tag gdb-main -- gdb work/chall
```

Command output is stored under `logs/` with metadata, stdout, stderr, hashes, duration, and exit code. Identical commands are skipped unless `--force` is supplied. Cache is good for recon; use `--force` when target state may change.

## 7. State discipline

Update state only through `ctfctl`:

```bash
./tools/ctfctl state fact add "Target exposes HTTP on port 80" --evidence LOG-000001
./tools/ctfctl state hypothesis add "Login may accept SQL injection" \
  --test "Compare id=1 and id=1'" \
  --expected "Different status, body, error, or timing"
./tools/ctfctl state hypothesis update H-0001 --status CONFIRMED --result "Response differs"
./tools/ctfctl state technique "Default credentials admin:admin" failed --evidence LOG-000004
./tools/ctfctl state next "Diff authenticated and unauthenticated responses" --objective "Identify access control flaw"
```

State transitions:

```text
INIT → AUTHORIZED → RECON → HYPOTHESIS → TESTING → EXPLOITATION → VERIFICATION → SOLVED
```

Any state may become `BLOCKED` or `ABANDONED`. Transition with a reason and evidence:

```bash
./tools/ctfctl state transition EXPLOITATION \
  --reason "Crash gives saved RIP control" \
  --evidence LOG-000012
```

## 8. Evidence discipline

Register meaningful observations:

```bash
./tools/ctfctl evidence add \
  --source LOG-000002 \
  --observation "GET / returned HTTP 200 and a login form" \
  --meaning "The primary attack surface is likely the authentication flow"
```

Every fact and hypothesis should cite evidence. Failed tests are also evidence. Never summarize a failure as only “it did not work”; record the command, response, and classification.

## 9. Specialist routing

Start with the orchestrator. Escalate deliberately:

- **Level 0:** simple challenge, orchestrator only.
- **Level 1:** category-specific specialist (`ctf-agent-web`, `ctf-agent-pwn`, `ctf-agent-rev`).
- **Level 2:** multiple specialists for independent hypotheses or heavy analysis.
- **Level 3:** independent `ctf-agent-verification` before final success claims.

Generate a handoff:

```bash
./tools/ctfctl handoff ctf-agent-web \
  --objective "Map HTTP routes and parameters" \
  --input state.yaml \
  --input logs/ \
  --constraint "No request outside .scope.yaml" \
  --constraint "Prefer single requests before fuzzing"
```

Specialists must return `reports/result-<agent>.json` using `templates/agent-result.json`. They do not directly edit canonical state. Merge their result:

```bash
./tools/ctfctl merge-result reports/result-web.json
```

## 10. Web workflow

1. Inventory root, robots, sitemap, obvious source/backup files, and redirects.
2. Build a parameter and route table.
3. Identify authentication/session behavior.
4. Compare minimal benign requests before payloads.
5. Test one hypothesis at a time.
6. Save every request and response.
7. Use browser tooling only when JavaScript or interaction is necessary.
8. Escalate from targeted requests to small dictionaries only after a reason exists.

Do not launch broad scans by default.

## 11. Pwn workflow

1. Copy the binary from `original/` to `work/`.
2. Run `ctfctl tool elf`.
3. Read protections and symbols before proposing an exploit.
4. Reproduce normal behavior.
5. Find the vulnerable function and a deterministic crash input.
6. Determine offsets with cyclic patterns or debugger evidence.
7. Build the shortest local exploit.
8. Move to remote only after local reproduction.
9. Save every crash input, debugger transcript, and remote transcript.

A crash is not code execution. Local success is not remote success.

## 12. Reverse workflow

1. Run `ctfctl tool elf`.
2. Run `ctfctl tool ghidra`; reuse cached results.
3. Extract binary facts, key functions, data flow, and validation logic.
4. Write semantic pseudocode before guessing.
5. Dynamically test only a candidate input or branch hypothesis.
6. Do not execute unknown binaries outside `work/` and an appropriate sandbox.

## 13. Flag lifecycle

Allowed states:

```text
NONE → DETECTED → CANDIDATE → REPRODUCED → SUBMITTED → ACCEPTED
```

Failure states include `FALSE_POSITIVE`, `REJECTED`, and `EXPIRED`.

Commands:

```bash
./tools/ctfctl flag detect
./tools/ctfctl flag candidate --value 'flag{example}' --source LOG-000101
./tools/ctfctl flag verify --replay 'python3 scripts/solve.py' --runs 2
./tools/ctfctl flag submit \
  --url https://ctfd.example/api/v1/flags \
  --token-env CTFD_TOKEN \
  --challenge-id 12
```

`submit` is dry-run by default. Actual submission requires `--yes`, an authorized platform, `allow_flag_submission` in `.scope.yaml`, and no active `no_auto_submit` operator constraint. If the operator later approves submission, remove that constraint explicitly before submitting. A platform HTTP 200 is not acceptance; the response must semantically confirm acceptance.

## 14. Final output

Before claiming a solve, produce a final report:

```bash
./tools/ctfctl report final \
  --root-cause "..." \
  --attack-path "Recon" \
  --attack-path "Exploit" \
  --exploit "scripts/solve.py" \
  --verification "Reproduced twice in LOG-000101 and LOG-000102" \
  --lesson "..."
```

Final answers must use this structure:

```text
Status:
SOLVED / PARTIAL / BLOCKED

Verified Facts:
- ...

Evidence:
- LOG-...
- E-...

Root Cause:
...

Attack Path:
1. ...

Verification:
...

Flag:
Only when REPRODUCED or ACCEPTED, as allowed by the event.

Next Action:
...
```

## 15. Stop-and-ask conditions

Ask the operator before:

- attacking a new host, port, or service;
- broad or high-rate scanning;
- destructive commands;
- running an untrusted binary outside a sandbox;
- uploading challenge data externally;
- repeated crashing after three failures without new evidence;
- automatic flag submission;
- spending substantial time on a low-confidence hypothesis.

## 16. Optimization implementation plan

The delegated engineering roadmap is maintained in [`docs/OPTIMIZATION_PLAN.md`](docs/OPTIMIZATION_PLAN.md).
It is the implementation contract for AI developers working on runtime hardening,
concurrency safety, evidence validation, execution policy, specialist merge idempotency,
HTTP sessions, and future performance work.

Before making optimization changes:

1. Read the relevant phase and acceptance criteria in that document.
2. Respect the assigned file ownership and do not modify another developer's write scope.
3. Add regression tests for every behavior change.
4. Report changed files, compatibility impact, tests, unresolved issues, risks, and rollback.
5. Do not treat this plan as evidence that any implementation task is already complete.

## 17. Efficiency rules

1. Reuse cached Ghidra and recon output.
2. Read structured JSON/summaries before raw large outputs.
3. Avoid repeating failed payload classes.
4. Keep one active hypothesis per test.
5. Prefer deterministic reproduction over random retries.
6. Record the next action after every work cycle.
7. Stop when no new evidence is being produced.
