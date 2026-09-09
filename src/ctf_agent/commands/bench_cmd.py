"""bench command handler (capability benchmark suite)."""
from __future__ import annotations

from pathlib import Path

from .. import bench as bench_module
from .common import json_print


def _handle_bench(args) -> int:
    suite = Path(args.suite) if args.suite else bench_module.DEFAULT_SUITE
    out = Path(args.out) if args.out else bench_module.DEFAULT_OUT
    summary = bench_module.run_suite(
        suite_dir=suite,
        out_dir=out,
        only=args.only,
        timeout=args.timeout,
    )
    counts = summary["counts"]
    json_print(
        {
            "run_dir": summary["run_dir"],
            "total": summary["total"],
            "counts": counts,
        }
    )
    if counts.get("FAILED", 0) or counts.get("ERROR", 0):
        return 1
    return 0


HANDLERS = {"bench": _handle_bench}
