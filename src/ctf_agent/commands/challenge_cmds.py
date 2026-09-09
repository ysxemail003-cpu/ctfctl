"""Challenge/workspace commands: init, import, current, use, intake, context."""
from __future__ import annotations

import sys
from pathlib import Path

from ..adapters import ingest as ingest_adapter
from ..challenge import (
    find_challenge_dir,
    get_current_challenge,
    init_challenge,
    list_challenges,
    resolve_challenge_selector,
    set_current_challenge,
)
from ..context import build_context, render_context_markdown
from ..intake import parse_intent
from .common import ROOT, challenge_dir_arg, json_print


def _handle_init(args) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    path = init_challenge(
        workspace=workspace,
        event=args.event,
        challenge=args.challenge,
        category=args.category,
        mode=args.mode,
        target=args.target,
        ports=args.port,
        confirm_authorization=args.confirm_authorization,
        constraints=args.constraint,
    )
    if not args.no_current:
        set_current_challenge(ROOT / "workspace", path)
    print(str(path))
    return 0


def _handle_import_files(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    json_print(
        ingest_adapter.import_files(
            challenge_dir,
            args.path,
            not args.no_recon,
            args.timeout,
        )
    )
    return 0


def _handle_current(args) -> int:
    selected = get_current_challenge(ROOT / "workspace")
    if selected is None:
        if args.json:
            json_print({"current": None})
        else:
            print("No current challenge.")
        return 0
    data = build_context(selected, max_logs=1)
    if args.json:
        json_print(
            {
                "current": True,
                "path": str(selected),
                "challenge": data.get("challenge"),
                "status": data.get("status"),
            }
        )
    else:
        challenge = data.get("challenge", {})
        print(f"Current: {challenge.get('event')}/{challenge.get('name')}")
        print(f"Path: {selected}")
        print(f"Status: {data.get('status')}")
        print(f"Next: {data.get('next_action')}")
    return 0


def _handle_challenges(args) -> int:
    items = list_challenges(ROOT / "workspace")
    if args.json:
        json_print(items)
    else:
        if not items:
            print("No challenges found.")
        for item in items:
            marker = "*" if item.get("current") else " "
            print(
                f"{marker} {item.get('event')}/{item.get('challenge')} "
                f"[{item.get('category')}] {item.get('status')} -> {item.get('path')}"
            )
    return 0


def _handle_use(args) -> int:
    challenge_dir = resolve_challenge_selector(Path(args.workspace).expanduser(), args.selector)
    record = set_current_challenge(ROOT / "workspace", challenge_dir)
    json_print(record)
    return 0


def _handle_intake(args) -> int:
    text = sys.stdin.read() if args.text == "-" else args.text
    intent = parse_intent(text)
    if args.markdown:
        lines = ["# Intake", ""]
        for key, value in intent.items():
            lines.append(f"- {key}: `{value}`")
        print("\n".join(lines))
    else:
        json_print(intent)
    return 0


def _handle_context(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    data = build_context(challenge_dir, max_logs=args.max_logs)
    if args.markdown:
        print(render_context_markdown(data))
    else:
        json_print(data)
    return 0


def _handle_status(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    data = build_context(challenge_dir, max_logs=5)
    status = {
        "challenge": data.get("challenge"),
        "status": data.get("status"),
        "objective": data.get("objective"),
        "next_action": data.get("next_action"),
        "fact_count": len(data.get("facts", [])),
        "open_hypotheses": data.get("open_hypotheses", []),
        "failed_technique_count": len(data.get("failed_techniques", [])),
        "flag": data.get("flag"),
        "decisions": data.get("decisions"),
    }
    if args.markdown:
        challenge = status.get("challenge", {})
        print(f"Challenge: {challenge.get('event')}/{challenge.get('name')}")
        print(f"Status: {status.get('status')}")
        print(f"Objective: {status.get('objective')}")
        print(f"Next: {status.get('next_action')}")
        print(f"Facts: {status.get('fact_count')}")
        print(f"Open hypotheses: {len(status.get('open_hypotheses', []))}")
        print(f"Flag: {status.get('flag', {}).get('status')}")
        decisions = status.get("decisions", [])
        if decisions:
            print("Decisions needed:")
            for decision in decisions:
                print(f"- {decision}")
    else:
        json_print(status)
    return 0


HANDLERS = {
    "init": _handle_init,
    "import-files": _handle_import_files,
    "current": _handle_current,
    "challenges": _handle_challenges,
    "list": _handle_challenges,
    "use": _handle_use,
    "intake": _handle_intake,
    "context": _handle_context,
    "status": _handle_status,
}
