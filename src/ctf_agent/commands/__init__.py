"""Per-domain CLI command handlers (split from the historical cli.py)."""
from __future__ import annotations

from typing import Any, Callable

from . import admin, bench_cmd, challenge_cmds, evidence_cmd, flag_cmd, logs_cmd, report_cmd, run_cmd, scope_cmd, solve_cmd, state_cmd, tool_cmd

HANDLERS: dict[str, Callable[[Any], int]] = {}
for _module in (
    admin,
    bench_cmd,
    challenge_cmds,
    evidence_cmd,
    flag_cmd,
    logs_cmd,
    report_cmd,
    run_cmd,
    scope_cmd,
    solve_cmd,
    state_cmd,
    tool_cmd,
):
    HANDLERS.update(_module.HANDLERS)

__all__ = ["HANDLERS"]
