"""evidence command handler."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..evidence import EvidenceLedger
from .common import challenge_dir_arg, json_print


def _handle_evidence(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    ledger = EvidenceLedger(challenge_dir)
    if args.evidence_command == "show":
        json_print(ledger.records())
    elif args.evidence_command == "add":
        json_print(
            ledger.add(
                args.source,
                args.observation,
                args.meaning,
                args.confidence,
                args.classification,
            )
        )
    return 0


HANDLERS = {"evidence": _handle_evidence}
