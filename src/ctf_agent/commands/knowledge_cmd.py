"""knowledge command handlers (cross-challenge ledger + review, Phase G)."""
from __future__ import annotations

from pathlib import Path

from .. import knowledge as knowledge_module
from ..challenge import find_challenge_dir
from .common import ROOT, challenge_dir_arg, json_print


def _workspace_arg(args) -> Path:
    return Path(args.workspace) if getattr(args, "workspace", None) else ROOT / "workspace"


def _handle_knowledge(args) -> int:
    if args.knowledge_command == "add":
        challenge_dir = find_challenge_dir(challenge_dir_arg(args))
        entry = knowledge_module.add_entry(
            challenge_dir,
            category=args.category,
            technique=args.technique,
            trigger=args.trigger,
            conclusion=args.conclusion,
            outcome=args.outcome,
            evidence_refs=args.evidence,
        )
        json_print(entry)
        return 0
    if args.knowledge_command == "list":
        entries = knowledge_module.list_entries(
            _workspace_arg(args), category=args.category, outcome=args.outcome
        )
        json_print({"total": len(entries), "entries": entries})
        return 0
    if args.knowledge_command == "propose":
        proposals = knowledge_module.propose_from_workspace(_workspace_arg(args))
        json_print({"total": len(proposals), "proposals": proposals})
        return 0
    if args.knowledge_command == "review":
        challenge_dir = find_challenge_dir(challenge_dir_arg(args))
        json_print(knowledge_module.generate_review(challenge_dir))
        return 0
    if args.knowledge_command == "stats":
        json_print(knowledge_module.stats(_workspace_arg(args)))
        return 0
    raise ValueError(f"Unhandled knowledge command: {args.knowledge_command}")


HANDLERS = {"knowledge": _handle_knowledge}
