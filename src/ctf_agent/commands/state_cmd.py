"""state command handler."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..errors import CTFError
from ..state import StateStore
from .common import challenge_dir_arg, json_print


def _handle_state(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    store = StateStore(challenge_dir)
    if args.state_command == "show":
        json_print(store.load())
    elif args.state_command == "render":
        print(store.render())
    elif args.state_command == "transition":
        store.transition(args.status, args.reason, args.evidence)
        json_print(store.load())
    elif args.state_command == "fact":
        if args.fact_command == "add":
            json_print(
                store.add_fact(
                    args.statement,
                    args.evidence,
                    args.confidence,
                    args.classification,
                )
            )
        else:
            raise CTFError("Unsupported fact operation")
    elif args.state_command == "hypothesis":
        if args.hypothesis_command == "add":
            json_print(
                store.add_hypothesis(
                    args.statement,
                    args.test,
                    args.expected,
                    args.confidence,
                    args.evidence,
                )
            )
        elif args.hypothesis_command == "update":
            json_print(store.update_hypothesis(args.id, args.status, args.result))
        else:
            raise CTFError("Unsupported hypothesis operation")
    elif args.state_command == "technique":
        json_print(
            store.add_technique(
                args.technique,
                args.outcome,
                args.evidence,
                args.classification,
            )
        )
    elif args.state_command == "constraint":
        if args.constraint_command == "set":
            json_print(store.set_constraints(args.value))
        elif args.constraint_command == "remove":
            json_print(store.remove_constraint(args.value))
        else:
            raise CTFError("Unsupported constraint operation")
    elif args.state_command == "next":
        json_print(store.set_next(args.next, args.objective))
    return 0


HANDLERS = {"state": _handle_state}
