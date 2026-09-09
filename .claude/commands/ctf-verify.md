---
description: Verify a candidate CTF flag by replaying the solver
allowed-tools: Bash(./tools/ctfctl *)
---

Read state and identify the current candidate flag. If a solver exists, run:

```bash
./tools/ctfctl flag verify --replay '<solver command>' --runs 2
```

Report the result with log IDs. Do not claim SOLVED unless reproduction succeeds.
