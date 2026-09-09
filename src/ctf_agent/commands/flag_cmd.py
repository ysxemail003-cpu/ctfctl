"""flag lifecycle command handlers."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..errors import CTFError
from ..flag import candidate as flag_candidate
from ..flag import detect as flag_detect
from ..flag import submit as flag_submit
from ..flag import verify_replay as flag_verify
from .common import challenge_dir_arg, json_print


def _handle_flag(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    if args.flag_command == "detect":
        matches = flag_detect(challenge_dir, args.pattern, args.limit)
        if args.json:
            json_print(matches)
        else:
            for item in matches:
                print(f"{item['file']}: {item['value']}")
            if not matches:
                print("No flag candidates found.")
        return 0
    if args.flag_command == "candidate":
        json_print(flag_candidate(challenge_dir, args.value, args.source, args.command, args.pattern))
        return 0
    if args.flag_command == "verify":
        result = flag_verify(
            challenge_dir,
            args.replay,
            args.runs,
            args.expected,
            args.pattern,
            args.timeout,
            args.network,
            args.target,
            args.port,
        )
        json_print(result)
        return 0
    if args.flag_command == "submit":
        result = flag_submit(
            challenge_dir,
            args.url,
            args.token_env,
            args.challenge_id,
            args.value,
            args.yes,
        )
        json_print(result)
        return 0
    raise CTFError(f"Unhandled command: {args.root_command}")


HANDLERS = {"flag": _handle_flag}
