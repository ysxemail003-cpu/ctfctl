"""run / tty command execution handlers."""
from __future__ import annotations

from ..runner import run_command, run_tty
from ..challenge import find_challenge_dir
from .common import challenge_dir_arg, command_rest, parse_env


def _handle_run(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    command = command_rest(args)
    env_vars = dict(parse_env(item) for item in getattr(args, "env", []))
    if args.root_command == "run":
        result = run_command(
            challenge_dir,
            command,
            tag=args.tag,
            classification=args.classification,
            network=args.network,
            target=args.target,
            port=args.port,
            timeout=args.timeout,
            force=args.force,
            quiet=args.quiet,
            print_limit=args.print_limit,
            input_file=args.input_file,
            env_vars=env_vars,
        )
    else:
        result = run_tty(
            challenge_dir,
            command,
            tag=args.tag,
            classification=args.classification,
            network=args.network,
            target=args.target,
            port=args.port,
            timeout=args.timeout,
        )
    return int(result.get("exit_code", 1))


HANDLERS = {"run": _handle_run, "tty": _handle_run}
