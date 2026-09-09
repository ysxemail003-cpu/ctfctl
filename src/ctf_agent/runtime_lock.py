"""Challenge-level runtime lock for serialized mutations.

Canonical challenge files (``state.yaml``, ``events.jsonl``,
``evidence.log``, log metadata, flag records, merge history) must only be
mutated while holding the challenge lock.

Design:

- Cross-process exclusion: Linux ``fcntl.flock`` on ``.runtime.lock``.
- In-process exclusion: a registry keeps ONE open file descriptor per
  challenge path and tracks the owning thread id. Only the owner may enter;
  other threads poll until the owner releases (no per-entry RLock, so there
  is no delete/release race).
- Reentrancy: the same thread may nest acquisitions (depth counter), which is
  what lets ``merge -> add_fact -> event`` reuse the lock without deadlocking.

The lock is therefore safe for multiple threads *and* multiple processes
operating on the same challenge.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .errors import CTFError

LOCK_FILE_NAME = ".runtime.lock"
DEFAULT_TIMEOUT_SECONDS = 30.0
FLOCK_POLL_SECONDS = 0.02


class ChallengeLockError(CTFError):
    """Raised when a challenge runtime lock cannot be acquired in time."""


@dataclass
class _Entry:
    fd: int = -1
    owner: int | None = None  # threading.get_ident() of the owning thread
    depth: int = 0


_registry: dict[str, _Entry] = {}
_registry_guard = threading.Lock()


def lock_path(challenge_dir: Path) -> Path:
    return Path(challenge_dir).resolve() / LOCK_FILE_NAME


def _key(challenge_dir: Path) -> str:
    return str(lock_path(challenge_dir))


def _open_fd(path: Path) -> int:
    os.makedirs(path.parent, exist_ok=True)
    return os.open(path, os.O_CREAT | os.O_RDWR, 0o644)


def acquire(challenge_dir: Path, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> bool:
    """Acquire the challenge lock, waiting up to ``timeout`` seconds."""
    path = lock_path(challenge_dir)
    key = str(path)
    me = threading.get_ident()
    deadline = time.monotonic() + timeout

    # Claim ownership (or bump depth for the current owner).
    while True:
        with _registry_guard:
            entry = _registry.setdefault(key, _Entry())
            if entry.owner == me:
                entry.depth += 1
                return True
            if entry.owner is None:
                if entry.fd < 0:
                    entry.fd = _open_fd(path)
                entry.owner = me
                entry.depth = 1
                break  # now try the flock below
        if time.monotonic() >= deadline:
            return False
        time.sleep(FLOCK_POLL_SECONDS)

    # Acquire the OS-level lock for our (single, cached) file descriptor.
    while True:
        try:
            fcntl.flock(entry.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                with _registry_guard:
                    if entry.fd >= 0:
                        os.close(entry.fd)
                    entry.fd = -1
                    entry.owner = None
                    entry.depth = 0
                raise
            if time.monotonic() >= deadline:
                with _registry_guard:
                    if entry.fd >= 0:
                        os.close(entry.fd)
                    entry.fd = -1
                    entry.owner = None
                    entry.depth = 0
                return False
            time.sleep(FLOCK_POLL_SECONDS)


def release(challenge_dir: Path) -> None:
    """Release a lock previously acquired by the calling thread."""
    key = _key(challenge_dir)
    me = threading.get_ident()
    with _registry_guard:
        entry = _registry.get(key)
        if entry is None or entry.owner != me or entry.depth <= 0:
            raise ChallengeLockError(
                f"Runtime lock for {challenge_dir} is not held by this thread"
            )
        entry.depth -= 1
        if entry.depth == 0:
            try:
                if entry.fd >= 0:
                    fcntl.flock(entry.fd, fcntl.LOCK_UN)
            finally:
                if entry.fd >= 0:
                    os.close(entry.fd)
                entry.fd = -1
                entry.owner = None
    # The entry stays cached, but the fd is closed so fork()ed children never
    # share an open file description (which would defeat cross-process flock).


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
