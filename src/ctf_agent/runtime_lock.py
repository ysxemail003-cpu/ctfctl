"""Challenge-level runtime lock for serialized mutations.

Canonical challenge files (``state.yaml``, ``events.jsonl``,
``evidence.jsonl``, log metadata, flag records, merge history) must only be
mutated while holding the challenge lock. The lock uses Linux ``fcntl.flock``
for cross-process exclusion and a per-process registry so nested acquisitions
by the same thread reuse the already-held flock instead of deadlocking::

    with challenge_lock(challenge_dir, description="state update"):
        ...
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .errors import CTFError

LOCK_FILE_NAME = ".runtime.lock"
DEFAULT_TIMEOUT_SECONDS = 30.0
FLOCK_POLL_SECONDS = 0.05


class ChallengeLockError(CTFError):
    """Raised when a challenge runtime lock cannot be acquired in time."""


@dataclass
class _HeldLock:
    path: Path
    fd: int = -1
    depth: int = 0
    guard: threading.RLock = field(default_factory=threading.RLock)


_registry: dict[str, _HeldLock] = {}
_registry_guard = threading.Lock()


def lock_path(challenge_dir: Path) -> Path:
    return Path(challenge_dir).resolve() / LOCK_FILE_NAME


def _key(challenge_dir: Path) -> str:
    return str(lock_path(challenge_dir))


def acquire(challenge_dir: Path, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> bool:
    """Acquire the challenge lock, waiting up to ``timeout`` seconds."""
    challenge_dir = Path(challenge_dir).resolve()
    key = _key(challenge_dir)
    with _registry_guard:
        held = _registry.get(key)
        if held is None:
            held = _HeldLock(path=lock_path(challenge_dir))
            _registry[key] = held
    # In-process mutual exclusion. Reentrant for the owning thread, so nested
    # mutations (merge -> add_fact -> event) do not deadlock.
    if not held.guard.acquire(timeout=timeout):
        return False
    try:
        if held.depth == 0:
            if not _flock_exclusive(held, timeout=timeout):
                held.guard.release()
                return False
        held.depth += 1
        return True
    except BaseException:
        held.guard.release()
        raise


def release(challenge_dir: Path) -> None:
    """Release a lock previously acquired by this process."""
    challenge_dir = Path(challenge_dir).resolve()
    key = _key(challenge_dir)
    with _registry_guard:
        held = _registry.get(key)
        if held is None or held.depth <= 0:
            raise ChallengeLockError(
                f"Runtime lock for {challenge_dir} is not held by this process"
            )
        held.depth -= 1
        if held.depth == 0:
            if held.fd >= 0:
                try:
                    fcntl.flock(held.fd, fcntl.LOCK_UN)
                finally:
                    os.close(held.fd)
                    held.fd = -1
            del _registry[key]
    held.guard.release()


def _flock_exclusive(held: _HeldLock, timeout: float) -> bool:
    if held.fd < 0:
        os.makedirs(held.path.parent, exist_ok=True)
        held.fd = os.open(held.path, os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(held.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                raise
            if time.monotonic() >= deadline:
                if held.fd >= 0:
                    os.close(held.fd)
                    held.fd = -1
                return False
            time.sleep(FLOCK_POLL_SECONDS)


@contextlib.contextmanager
def challenge_lock(
    challenge_dir: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    description: str = "",
) -> Iterator[None]:
    """Context manager that holds the challenge lock while the body runs."""
    challenge_dir = Path(challenge_dir).resolve()
    if not acquire(challenge_dir, timeout=timeout):
        suffix = f" ({description})" if description else ""
        raise ChallengeLockError(
            f"Could not acquire challenge lock for {challenge_dir}{suffix} "
            f"within {timeout:g}s; another agent/process may hold it"
        )
    try:
        yield
    finally:
        release(challenge_dir)
