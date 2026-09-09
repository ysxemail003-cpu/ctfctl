# Security

ctf-agent is an agent runtime that executes commands and may run untrusted
challenge binaries inside a Kali VM. The project's own safeguards — scope
checks, evidence refs, redaction, budget ledger, process-group timeouts,
dry-run flag submission — are design invariants, not optional features.

## Reporting a vulnerability

Please do **not** open a public issue for security findings. Report privately to
the maintainer email listed in `pyproject.toml` / the repository profile
(replace the placeholder below before release):

```
maintainer: ysxemail001@163.com
```

Include: affected version/commit, a minimal reproduction, impact, and whether
the issue involves a running challenge.

## What we care about most

- **Scope escape**: any path/URL/host that bypasses `.scope.yaml`
  (traversal, symlinks, redirects, cross-host downloads, sandbox escapes).
- **Evidence forgery**: making a claim resolvable to a `LOG-*`/`E-*` without a
  real artifact, or editing generated projections to fake state.
- **Secret leakage**: credentials/tokens written to logs, artifacts, trajectory
  exports, or the git history (tokens must stay in the environment).
- **Lock/correctness**: concurrent writers corrupting `state.yaml`, logs,
  evidence, or flag records (the runtime lock is thread- and process-safe).
- **Runaway execution**: commands escaping timeouts/output caps or leaving
  orphaned child processes.

## Our release hygiene

- Real challenge data is never committed; `workspace/` only tracks structure.
- `make scan-secrets` greps the whole git history for high-signal patterns and
  should be clean before any release.
- `.gitignore` keeps `.venv`, caches, coverage, `bench/results/` and core dumps
  out of the tree.
