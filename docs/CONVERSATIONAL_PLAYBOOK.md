# Conversational CTF Playbook

This document defines the user-facing experience. The operator should be able to say what they want in natural language; the agent translates that into safe runtime actions.

## Operator phrases and agent behavior

| Operator says | Agent action |
|---|---|
| “帮我解这道 Web 题，目标…” | Parse intake, confirm blocking scope details, initialize, run web inventory, report checkpoint |
| “这是一道 Pwn 题，文件在…” | Initialize, copy file, file/ELF recon, run local behavior, form hypotheses |
| “继续” | `ctfctl context`, resume `next_action`, avoid cached repeats |
| “当前状态” | `ctfctl status` / `ctfctl context`, summarize facts and hypotheses |
| “为什么？” | Cite exact `LOG-*` / `E-*` / artifact evidence |
| “换个方向” | Mark current hypothesis inconclusive, choose a different supported hypothesis |
| “不要提交 flag” | Preserve constraint; ask before submission |
| “提交” | Require reproduced flag and explicit authorization |
| “生成报告” | Generate final report with root cause, path, evidence, and verification |

## Standard checkpoint

```text
Status:
RECON

Verified Facts:
- GET / returned a login form [LOG-000003]

Current Hypothesis:
- H-0001: Login input may be injectable
- Test: Compare admin and admin'
- Expected: Status/body/error/redirect/timing difference

Failed:
- Default credentials admin:admin [LOG-000005]

Next:
Send three minimal requests and diff responses.

Decision needed:
None
```

## Intake decision tree

1. If authorization is unclear → ask once for event rules and AI mode.
2. If category is web/pwn and target is absent → ask once for host and ports.
3. If a file is required and absent → ask once for the path.
4. If flag-submission policy is absent → default to “ask before submit”.
5. Otherwise initialize and proceed.

Do not ask for command choices when the agent can infer a safe minimal next action.

## Continuation

At the start of a CTF conversation:

```bash
./tools/ctfctl current
./tools/ctfctl context --markdown
```

The current pointer survives new Claude/Codex sessions. `ctfctl use EVENT/CHALLENGE` switches challenges. The operator can say “切换到 pwn-easy”; the agent resolves the selector.

## Context efficiency

- Use `ctfctl context` instead of rereading every raw log.
- Use structured adapter output before raw bodies.
- Reuse Ghidra and command caches.
- Record only decisive strings and artifacts in state.
- Keep one active hypothesis per test.
- Stop after three similar failures without new evidence and reassess.

## Safety

The agent may continue automatically only inside `.scope.yaml`. It must ask before target expansion, broad scanning, destructive actions, external upload, untrusted execution outside `work/`, or automatic flag submission.
