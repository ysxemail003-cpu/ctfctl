"""Execution policy primitives: path safety and budget projection.

Developer D provides these pure policy interfaces; the runner, scope checks,
and adapters call them. Nothing in this module executes commands or touches
canonical state.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .errors import CTFError

USAGE_FIELDS = ("requests", "scan_ports", "runtime_seconds", "concurrent_commands")


class PolicyError(CTFError):
    """Raised when an action violates execution policy."""


def is_inside(root: Path, candidate: str | Path) -> bool:
    root = Path(root).expanduser().resolve()
    candidate = Path(candidate).expanduser().resolve()
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_inside(root: Path, candidate: str | Path) -> Path:
    """Resolve *candidate* (relative to *root*) and require containment.

    Symlinks are resolved first, so a symlink pointing outside *root* is
    rejected rather than silently followed.
    """
    root = Path(root).expanduser().resolve()
    path = Path(candidate).expanduser()
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise PolicyError(f"Cannot resolve path {candidate}: {exc}") from exc
    if not is_inside(root, resolved):
        raise PolicyError(f"Path escapes the challenge directory: {candidate}")
    return resolved


def ensure_inside(root: Path, *candidates: str | Path) -> None:
    for candidate in candidates:
        resolve_inside(root, candidate)


def ensure_not_original(challenge_dir: Path, *candidates: str | Path) -> None:
    """Reject operations that would modify original/ inputs."""
    original = (challenge_dir / "original").resolve()
    for candidate in candidates:
        resolved = resolve_inside(challenge_dir, candidate)
        if is_inside(original, resolved):
            raise PolicyError(f"Refusing to modify immutable original/: {candidate}")


def project_usage(usage: Mapping[str, Any], deltas: Mapping[str, int]) -> dict[str, int]:
    projected: dict[str, int] = {field: int(usage.get(field, 0)) for field in USAGE_FIELDS}
    for field in USAGE_FIELDS:
        projected[field] += int(deltas.get(field, 0))
    return projected


def ensure_within_limits(
    limits: Mapping[str, Any],
    usage: Mapping[str, Any],
    deltas: Mapping[str, int] | None = None,
) -> dict[str, int]:
    """Return projected usage or raise :class:`PolicyError` on the first limits.

    A limit of zero or a missing limit means "unlimited" for that dimension.
    """
    projected = project_usage(usage, deltas or {})
    violations: list[str] = []

    max_requests = int(limits.get("max_requests") or 0)
    if max_requests and projected["requests"] > max_requests:
        violations.append(
            f"requests {projected['requests']} exceeds max_requests {max_requests}"
        )
    max_scan_ports = int(limits.get("max_scan_ports") or 0)
    if max_scan_ports and projected["scan_ports"] > max_scan_ports:
        violations.append(
            f"scan_ports {projected['scan_ports']} exceeds max_scan_ports {max_scan_ports}"
        )
    max_runtime_minutes = int(limits.get("max_runtime_minutes") or 0)
    if max_runtime_minutes and projected["runtime_seconds"] > max_runtime_minutes * 60:
        violations.append(
            f"runtime {projected['runtime_seconds']}s exceeds "
            f"max_runtime_minutes {max_runtime_minutes}"
        )
    max_concurrent = int(limits.get("max_concurrent_commands") or 0)
    if max_concurrent and projected["concurrent_commands"] > max_concurrent:
        violations.append(
            f"concurrent_commands {projected['concurrent_commands']} exceeds "
            f"max_concurrent_commands {max_concurrent}"
        )
    if violations:
        raise PolicyError("Budget limit exceeded: " + "; ".join(violations))
    return projected


def commit_usage(usage: Mapping[str, Any], deltas: Mapping[str, int]) -> dict[str, int]:
    """Return a new usage dict with *deltas* applied (no validation)."""
    return project_usage(usage, deltas)
