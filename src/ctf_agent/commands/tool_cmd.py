"""tool adapter commands (http, http-session, nmap, web-inventory, file, elf, ghidra)."""
from __future__ import annotations

from ..adapters import elf as elf_adapter
from ..adapters import ghidra as ghidra_adapter
from ..adapters import http as http_adapter
from ..adapters import nmap as nmap_adapter
from ..adapters import recon as recon_adapter
from ..challenge import find_challenge_dir
from ..errors import CTFError
from .common import challenge_dir_arg, json_print, parse_header


def _handle_tool(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    if args.tool_command == "http":
        headers = dict(parse_header(item) for item in args.header)
        result = http_adapter.request(
            challenge_dir,
            url=args.url,
            method=args.method,
            headers=headers,
            data=args.data,
            timeout=args.timeout,
            tag=args.tag,
            session=getattr(args, "session", None),
        )
        json_print(result)
        return 0
    if args.tool_command == "http-session":
        if args.action == "show":
            json_print(http_adapter.session_info(challenge_dir, args.session))
        else:
            json_print(http_adapter.replay_session(challenge_dir, args.session))
        return 0
    if args.tool_command == "nmap":
        json_print(
            nmap_adapter.scan(
                challenge_dir,
                args.target,
                args.port,
                not args.no_service,
                args.timeout,
            )
        )
        return 0
    if args.tool_command == "web-inventory":
        json_print(http_adapter.inventory(challenge_dir, args.url, args.timeout))
        return 0
    if args.tool_command == "file":
        json_print(recon_adapter.file_recon(challenge_dir, args.path, args.timeout))
        return 0
    if args.tool_command == "elf":
        json_print(elf_adapter.recon(challenge_dir, args.binary, args.timeout))
        return 0
    if args.tool_command == "ghidra":
        json_print(ghidra_adapter.export(challenge_dir, args.binary, args.force, args.timeout))
        return 0
    raise CTFError(f"Unhandled command: {args.root_command}")


HANDLERS = {"tool": _handle_tool}
