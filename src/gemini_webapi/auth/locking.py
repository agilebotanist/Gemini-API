"""Cross-process lock for the shared storage state.

The storage state is written by two independent programs (``gemini-web`` and
``notebooklm``) and by any number of their concurrent invocations. Every write is a
read-modify-write of one JSON file, so without mutual exclusion the last writer wins
and the other's rotated cookie is lost — which, for a rotating credential, means the
other tool is logged out.

The lock has to interoperate with NotebookLM's, so two properties are fixed and not
ours to change (ADR-0006):

* **The sentinel path** — ``.storage_state.json.lock`` beside the storage file,
  derived in :func:`gemini_webapi.auth.paths.storage_state_lock_path`.
* **The primitive** — an exclusive byte-range lock on byte 0 of that sentinel:
  ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows. Both are what NotebookLM's
  ``_auth.storage_lock`` takes, and a lock is only a lock if both sides take the same
  one.

A thread lock keyed on the resolved path sits in front of the OS lock, because
``flock`` is per-open-file-description: two threads in one process would each get
their own and neither would block.
"""

from __future__ import annotations

import contextlib
import errno
import os
import random
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

#: How long to keep retrying before giving up on a contended sentinel. Generous: the
#: critical section is a few-kilobyte JSON rewrite, so reaching this means another
#: process is wedged, and failing fast would surface as a spurious auth error.
DEFAULT_TIMEOUT_SECONDS = 30.0
_INITIAL_DELAY = 0.01
_MAX_DELAY = 0.25

_CONTENTION_ERRNOS = frozenset({errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES})

_thread_locks: dict[str, threading.Lock] = {}
_registry_guard = threading.Lock()


class LockTimeoutError(TimeoutError):
    """Raised when the sentinel could not be acquired within the timeout."""


def _thread_lock_for(path: Path) -> threading.Lock:
    """Return the process-wide thread lock for ``path``.

    Keyed on the resolved path so ``~/x``, ``./x`` and a symlink to ``x`` collapse to
    one key. An unresolvable path (a parent that does not exist yet) falls back to the
    absolute spelling rather than raising — the OS lock is still correct, only the
    in-process fast path degrades.
    """
    try:
        key = str(path.expanduser().resolve())
    except (OSError, RuntimeError):  # pragma: no cover - symlink loop / missing parent
        key = str(path.expanduser().absolute())
    with _registry_guard:
        lock = _thread_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _thread_locks[key] = lock
        return lock


def _os_lock(fd: int) -> bool:
    """Try to take the OS lock on byte 0 of ``fd``; ``False`` means contended."""
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in _CONTENTION_ERRNOS:
                return False
            raise
    else:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno in _CONTENTION_ERRNOS:
                return False
            raise


def _os_unlock(fd: int) -> None:
    """Release the OS lock on byte 0 of ``fd``, ignoring an already-released state."""
    with contextlib.suppress(OSError):
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def file_lock(
    sentinel: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    _sleep=time.sleep,
    _monotonic=time.monotonic,
) -> Iterator[None]:
    """Hold an exclusive cross-process lock on ``sentinel`` for the block's duration.

    The sentinel file is created if absent (0o600) and never deleted: deleting it
    races — a second process can create and lock a *new* inode while the first still
    holds the old one, and then both are inside the critical section.

    Raises :class:`LockTimeoutError` if the lock is still contended after ``timeout``
    seconds. The ``_sleep`` / ``_monotonic`` seams exist so tests can drive contention
    deterministically instead of by wall clock.
    """
    sentinel = sentinel.expanduser()
    sentinel.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    thread_lock = _thread_lock_for(sentinel)
    deadline = _monotonic() + timeout
    if not thread_lock.acquire(timeout=max(timeout, 0.0)):
        raise LockTimeoutError(f"Timed out waiting for the in-process lock on {sentinel.name}")

    fd = os.open(str(sentinel), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        delay = _INITIAL_DELAY
        while True:
            if _os_lock(fd):
                break
            if _monotonic() >= deadline:
                raise LockTimeoutError(
                    f"Timed out after {timeout:g}s waiting for {sentinel.name}. "
                    "Another gemini-web or notebooklm process may be writing the session."
                )
            # Jitter so several waiters do not retry in lockstep.
            _sleep(delay * (0.5 + random.random()))
            delay = min(delay * 2, _MAX_DELAY)
        try:
            yield
        finally:
            _os_unlock(fd)
    finally:
        os.close(fd)
        thread_lock.release()
