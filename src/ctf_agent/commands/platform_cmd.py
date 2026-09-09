"""platform command handlers (CTFd bridge, Phase D1)."""
from __future__ import annotations

from pathlib import Path

from ..adapters import ingest as ingest_adapter
from ..challenge import init_challenge
from ..platform import CTFdPlatform
from ..util import slugify
from .common import ROOT, json_print


def _handle_platform(args) -> int:
    platform = CTFdPlatform(args.url, args.token_env)
    if args.ctfd_command == "list":
        challenges = platform.list_challenges()
        json_print({"platform": "ctfd", "count": len(challenges), "challenges": challenges})
        return 0
    if args.ctfd_command == "pull":
        return _pull(platform, args)
    raise ValueError(f"Unhandled ctfd command: {args.ctfd_command}")


def _pull(platform: CTFdPlatform, args) -> int:
    event = slugify(args.event, "event")
    workspace = Path(args.workspace) if args.workspace else ROOT / "workspace"
    challenges = platform.list_challenges()
    if args.category:
        wanted = args.category.lower()
        challenges = [c for c in challenges if c.category.lower() == wanted]
    if args.max:
        challenges = challenges[: args.max]

    results = []
    for item in challenges:
        name = slugify(item.name, "challenge")
        challenge_dir = workspace / "contests" / event / name
        if challenge_dir.exists():
            results.append({"id": item.id, "name": item.name, "status": "skipped", "reason": "already exists"})
            continue
        detail = platform.challenge_detail(item.id)
        category = (detail.category or item.category or "misc").lower()
        created = init_challenge(
            workspace,
            event,
            detail.name or item.name,
            category,
            "AI_NATIVE",
            confirm_authorization=True,
            constraints=["no_auto_submit"],
        )
        downloaded: list[Path] = []
        if not args.no_attachments and detail.files:
            tmp = created / "work" / ".ctfd-downloads"
            tmp.mkdir(parents=True, exist_ok=True)
            for file_path in detail.files:
                downloaded.append(platform.download_file(file_path, tmp))
        if downloaded:
            ingest_adapter.import_files(created, downloaded, perform_recon=False)
        results.append(
            {
                "id": item.id,
                "name": detail.name or item.name,
                "status": "pulled",
                "challenge_dir": str(created),
                "attachments": len(downloaded),
                "constraint": "no_auto_submit",
            }
        )
    json_print({"platform": "ctfd", "event": event, "pulled": len(results), "results": results})
    return 0


HANDLERS = {"platform": _handle_platform}
