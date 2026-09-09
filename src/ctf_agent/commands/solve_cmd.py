"""solve command handler (Phase B solve loop)."""
from __future__ import annotations

from .. import backends as backends_module
from .. import solver as solver_module
from ..challenge import find_challenge_dir
from .common import challenge_dir_arg, json_print


def _handle_solve(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    backend = backends_module.get_backend(args.backend, cwd=challenge_dir)
    summary = solver_module.run_solve(
        challenge_dir,
        backend=backend,
        max_rounds=args.max_rounds,
        max_actions=args.max_actions,
        action_timeout=args.action_timeout,
        model_timeout=args.model_timeout,
    )
    json_print(summary.to_dict())
    return 0 if summary.status == "SOLVED" else 1


def _handle_race(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    if args.backends.strip().lower() == "auto":
        names = backends_module.available_backends()
        if not names:
            raise ValueError("No model backend available for racing; install codex/claude/gemini.")
    else:
        names = [name.strip() for name in args.backends.split(",") if name.strip()]
    backends = [backends_module.get_backend(name, cwd=challenge_dir) for name in names]
    record = solver_module.race_solve(
        challenge_dir,
        backends,
        per_worker_rounds=args.rounds,
        action_timeout=args.action_timeout,
        model_timeout=args.model_timeout,
    )
    json_print(record)
    return 0 if record["status"] == "SOLVED" else 1


HANDLERS = {"solve": _handle_solve, "race": _handle_race}
