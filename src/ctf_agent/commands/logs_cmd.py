"""logs command: summary and evidence-safe archival."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..logarchive import archive_logs, summary
from .common import challenge_dir_arg, json_print


def _handle_logs(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    if args.logs_command == "summary":
        json_print(summary(challenge_dir))
    elif args.logs_command == "archive":
        json_print(archive_logs(challenge_dir, dry_run=args.dry_run))
    return 0


HANDLERS = {"logs": _handle_logs}
