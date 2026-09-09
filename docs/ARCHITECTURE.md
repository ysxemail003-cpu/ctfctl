# Architecture

> Optimization and delegated implementation plan: [`OPTIMIZATION_PLAN.md`](OPTIMIZATION_PLAN.md).

## Design goals

1. **Evidence-first**: claims are grounded in logs and artifacts.
2. **Durable state**: work survives context compaction and agent restarts.
3. **Deliberate capability**: category specialists are used only when needed.
4. **Efficiency**: structured summaries and caches prevent repeated expensive work.
5. **Safety**: authorization, target scope, and flag submission are explicit.

## Conversational flow

```text
operator natural language
        │
        ├── ctfctl intake
        ├── ctfctl init / import-files
        ├── ctfctl current / context
        │
        └── orchestrator chooses the next minimal action
```

The operator does not need to know these commands. Claude Code and Codex invoke them internally.

## Runtime flow

```text
operator / orchestrator
        │
        ├── ctfctl init
        │      ├── .scope.yaml
        │      ├── state.yaml
        │      ├── STATE.md
        │      └── evidence files
        │
        ├── ctfctl run / ctfctl tool
        │      ├── scope check
        │      ├── subprocess or adapter
        │      ├── logs/LOG-*.json
        │      ├── stdout / stderr / transcript
        │      └── events.jsonl
        │
        ├── ctfctl state / evidence
        │      ├── facts
        │      ├── hypotheses
        │      ├── techniques
        │      └── EVIDENCE.md
        │
        ├── ctfctl handoff
        │      └── specialist agent
        │             └── reports/result-*.json
        │
        ├── ctfctl merge-result
        │
        ├── ctfctl flag verify
        │
        └── ctfctl report final
```

Command cache identity includes the command, working directory, effective
environment, input and challenge-local file hashes, network target/port, and
timeout. Changing any of these produces a new command log rather than reusing a
stale result.

## Canonical data

| File | Role | Edited by |
|---|---|---|
| `state.yaml` | Canonical challenge state | `ctfctl state` only |
| `STATE.md` | Human/LLM snapshot | Generated |
| `events.jsonl` | Append-only event history | Runtime |
| `evidence.jsonl` | Machine-readable evidence ledger | `ctfctl evidence` |
| `EVIDENCE.md` | Human-readable evidence ledger | Generated |
| `workspace/current.yaml` | Durable current-challenge pointer | `ctfctl use` / `ctfctl init` |
| `.scope.yaml` | Authorization and targets | `ctfctl scope` |
| `logs/*.json` | Command metadata | `ctfctl run` / adapters |
| `flags/flag.yaml` | Flag lifecycle | `ctfctl flag` |

## Specialist protocol

Specialists do not mutate canonical state directly. They receive a handoff and return a JSON result:

```text
handoff-<agent>.md → specialist → result-<agent>.json → merge-result
```

This prevents write conflicts and keeps specialist context small. The result schema is in `templates/agent-result.json`.

## Tool adapters

Adapters are intentionally narrow:

- `http`: authorized request, redirect revalidation, body, headers, forms, links, scripts, and structured summary.
- `web-inventory`: root, robots, sitemap, forms, links, and scripts.
- `nmap`: explicit-port scoped scan with XML parsing.
- `file`: file type, SHA-256, strings, and type-specific archive/PCAP/image handling.
- `elf`: `file`, SHA-256, `checksec --format=json`, and ELF header facts.
- `ghidra`: cached headless analysis, function list, and decompiled sources.
- `import-files`: immutable copy into `original/` with provenance and optional recon.

Other tools should use the generic `ctfctl run` wrapper. Do not wrap every Kali tool; add an adapter only when structured parsing materially improves agent accuracy.

## Flag lifecycle

```text
NONE
→ DETECTED
→ CANDIDATE
→ REPRODUCED
→ SUBMITTED
→ ACCEPTED
```

`REPRODUCED` requires at least two replay runs with the same flag or expected output. Actual submission additionally requires an explicitly approved `--yes` run, no `no_auto_submit` constraint, `allow_flag_submission`, a `REPRODUCED` flag, and a platform URL present in `.scope.yaml`. `ACCEPTED` additionally requires a semantic platform response. Submission is dry-run by default.

## Extension points

Add a new specialist by:

1. Creating `agent-specs/ctf-<name>.md` with YAML frontmatter.
2. Running `ctfctl sync-agents`.
3. Adding the generated skill to Codex with `--install-codex` when needed.

Add a new tool adapter by:

1. Implementing a function that returns structured JSON.
2. Saving raw artifacts under `artifacts/`.
3. Appending a runtime event.
4. Enforcing `.scope.yaml` for network actions.
5. Adding tests for parsing and scope rejection.
