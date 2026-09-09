"""Shared CLI helpers used by the per-domain command modules."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..errors import CTFError

#: Repository root: .../src/ctf_agent/commands/common.py -> repo root
ROOT = Path(__file__).resolve().parents[3]


def json_print(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def challenge_dir_arg(args: argparse.Namespace) -> str | None:
    return getattr(args, "challenge_dir", None) or getattr(args, "global_challenge_dir", None)


def parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise CTFError(f"Invalid header, expected 'Name: Value': {value}")
    key, val = value.split(":", 1)
    return key.strip(), val.strip()


def parse_env(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise CTFError(f"Invalid environment assignment, expected KEY=VALUE: {value}")
    key, val = value.split("=", 1)
    return key, val


def add_challenge_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-C",
        "--challenge-dir",
        help="Challenge directory containing state.yaml. Defaults to CTF_CHALLENGE_DIR or current directory.",
    )


def command_rest(args: argparse.Namespace) -> list[str]:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise CTFError("No command supplied. Usage: ctfctl run --tag NAME -- COMMAND [ARGS...]")
    return command
