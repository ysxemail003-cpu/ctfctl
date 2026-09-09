"""report commands: handoff, merge-result, report final."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..errors import CTFError
from ..report import final_report, handoff, merge_result
from .common import challenge_dir_arg, json_print


def _handle_handoff(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    path = handoff(challenge_dir, args.agent, args.objective, args.input, args.constraint)
    print(str(path))
    return 0


def _handle_merge_result(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    json_print(merge_result(challenge_dir, args.result))
    return 0


def _handle_report(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    if args.report_command == "final":
        path = final_report(
            challenge_dir,
            args.root_cause,
            args.attack_path,
            args.exploit,
            args.verification,
            args.lesson,
            args.output,
        )
        print(str(path))
        return 0
    raise CTFError(f"Unhandled command: {args.root_command}")


HANDLERS = {
    "handoff": _handle_handoff,
    "merge-result": _handle_merge_result,
    "report": _handle_report,
}
