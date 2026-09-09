"""scope command handler."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..scope import ScopeStore
from .common import challenge_dir_arg, json_print


def _handle_scope(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    scope_store = ScopeStore(challenge_dir)
    if args.scope_command == "show":
        json_print(scope_store.load())
    elif args.scope_command == "confirm":
        json_print(scope_store.confirm(args.notes))
    elif args.scope_command == "add-host":
        json_print(scope_store.add_host(args.host, args.port, args.description))
    elif args.scope_command == "check":
        json_print(scope_store.check(args.target, args.port))
    elif args.scope_command == "allow":
        json_print(scope_store.allow(args.capability))
    return 0


HANDLERS = {"scope": _handle_scope}
