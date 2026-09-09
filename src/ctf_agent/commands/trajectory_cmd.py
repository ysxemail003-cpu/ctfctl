"""trajectory command handlers (Phase D2)."""
from __future__ import annotations

from ..challenge import find_challenge_dir
from ..trajectory import export_trajectory
from .common import challenge_dir_arg, json_print


def _handle_trajectory(args) -> int:
    challenge_dir = find_challenge_dir(challenge_dir_arg(args))
    record = export_trajectory(challenge_dir)
    json_print(
        {
            "challenge": record["challenge"]["name"],
            "verdict": record["verdict"],
            "final_flag": record["final_flag"],
            "summary": record["summary"],
            "outputs": record["outputs"],
        }
    )
    return 0


HANDLERS = {"trajectory": _handle_trajectory}
