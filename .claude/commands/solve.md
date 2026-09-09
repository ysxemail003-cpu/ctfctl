---
description: Solve or continue an authorized CTF challenge from natural language
allowed-tools: Bash(./tools/ctfctl *), Read(**), Edit(workspace/**)
---

Use the `ctf-agent-orchestrator` behavior. Treat `$ARGUMENTS` as the operator's natural-language challenge request.

1. If this is a new challenge, run `./tools/ctfctl intake --text '...'`.
2. Ask only for blocking missing authorization/target/file information.
3. Initialize, recon, test, update state, and verify flags using `ctfctl`.
4. Report a compact checkpoint with evidence IDs.
5. Continue autonomously only within the authorized AI mode and scope.
6. Never claim a solve without reproduction.
