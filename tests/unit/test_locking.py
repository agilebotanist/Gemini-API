"""The cross-process lock: acquisition, contention, and the sentinel's lifecycle."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest

from gemini_webapi.auth import locking

from ._support import IsolatedHome

# Child program used for the real cross-process test: take the lock, report, hold.
_HOLDER = """
import sys, time
sys.path.insert(0, {src!r})
from pathlib import Path
from gemini_webapi.auth.locking import file_lock
with file_lock(Path({sentinel!r})):
    print("HELD", flush=True)
    time.sleep({hold})
"""


def _src_dir() -> str:
    import gemini_webapi

    return str(next(iter(gemini_webapi.__path__)).rsplit("gemini_webapi", 1)[0])


class TestFileLock(unittest.TestCase):
    def test_acquires_and_releases(self):
        with IsolatedHome() as home:
            sentinel = home.root / "profiles" / ".storage_state.json.lock"
            with locking.file_lock(sentinel):
                self.assertTrue(sentinel.exists())
            # Re-acquirable afterwards: a lock that leaked would hang here.
            with locking.file_lock(sentinel, timeout=2):
                pass

    def test_creates_the_parent_directory(self):
        with IsolatedHome() as home:
            sentinel = home.root / "deep" / "nested" / ".storage_state.json.lock"
            with locking.file_lock(sentinel):
                self.assertTrue(sentinel.parent.is_dir())

    def test_sentinel_survives_release(self):
        # Deleting it would race: another process could create and lock a *new* inode
        # while this one still holds the old, putting two writers in the section.
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            with locking.file_lock(sentinel):
                pass
            self.assertTrue(sentinel.exists())

    def test_owner_only_mode(self):
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            with locking.file_lock(sentinel):
                pass
            if sys.platform != "win32":
                self.assertEqual(sentinel.stat().st_mode & 0o077, 0)

    def test_different_paths_do_not_block_each_other(self):
        with IsolatedHome() as home:
            first = home.root / "a.lock"
            second = home.root / "b.lock"
            with locking.file_lock(first), locking.file_lock(second, timeout=2):
                pass

    def test_threads_serialise(self):
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            order: list[str] = []
            started = threading.Event()

            def worker() -> None:
                started.wait(2)
                with locking.file_lock(sentinel, timeout=10):
                    order.append("second")

            thread = threading.Thread(target=worker)
            with locking.file_lock(sentinel):
                thread.start()
                started.set()
                time.sleep(0.2)
                order.append("first")
            thread.join(10)
            self.assertEqual(order, ["first", "second"])

    def test_timeout_raises_when_another_process_holds_it(self):
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            script = _HOLDER.format(src=_src_dir(), sentinel=str(sentinel), hold=5)
            child = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                line = child.stdout.readline() if child.stdout else ""
                if "HELD" not in line:
                    self.skipTest(f"child could not take the lock: {line!r}")
                with self.assertRaises(locking.LockTimeoutError):
                    with locking.file_lock(sentinel, timeout=1.0):
                        pass  # pragma: no cover - must not be reached
            finally:
                child.kill()
                child.wait(10)

    def test_timeout_message_names_the_sentinel_and_the_culprits(self):
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            # Drive the retry loop without wall-clock waiting: a monotonic that jumps
            # past the deadline on its second read, and an always-contended lock.
            reads = iter([0.0, 0.0, 100.0, 100.0, 100.0])

            original = locking._os_lock
            locking._os_lock = lambda _fd: False
            try:
                with self.assertRaises(locking.LockTimeoutError) as ctx:
                    with locking.file_lock(
                        sentinel,
                        timeout=1.0,
                        _sleep=lambda _d: None,
                        _monotonic=lambda: next(reads, 100.0),
                    ):
                        pass  # pragma: no cover
            finally:
                locking._os_lock = original

            message = str(ctx.exception)
            self.assertIn(".storage_state.json.lock", message)
            self.assertIn("notebooklm", message)

    def test_lock_released_when_the_body_raises(self):
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            with self.assertRaises(RuntimeError):
                with locking.file_lock(sentinel):
                    raise RuntimeError("boom")
            with locking.file_lock(sentinel, timeout=2):
                pass

    def test_thread_lock_registry_collapses_path_spellings(self):
        with IsolatedHome() as home:
            sentinel = home.root / ".storage_state.json.lock"
            sentinel.touch()
            spelled = home.root / "." / ".storage_state.json.lock"
            self.assertIs(
                locking._thread_lock_for(sentinel),
                locking._thread_lock_for(spelled),
            )

    def test_os_lock_helpers_round_trip(self):
        with IsolatedHome() as home:
            sentinel = home.root / "raw.lock"
            fd = os.open(str(sentinel), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                self.assertTrue(locking._os_lock(fd))
                locking._os_unlock(fd)
                self.assertTrue(locking._os_lock(fd))
                locking._os_unlock(fd)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
