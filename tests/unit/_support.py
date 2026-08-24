"""Shared fixtures for the offline auth suite.

Three things every module here needs:

* **An isolated home.** The auth layer reads real user directories, and a test that
  writes to ``~/.notebooklm`` would break the developer's actual session. Every path
  is redirectable by environment variable precisely so tests can redirect them, and
  :class:`IsolatedHome` sets *all* of them — including the ones a test does not think
  it uses, because a missed variable means the test silently exercises the real home.
* **A known secret.** :data:`FAKE_PSID` looks like a real Google cookie (the ``g.a0``
  prefix and the length are what the scrubber's heuristics key on), so leak tests
  exercise the same code paths a real value would.
* **A fake browser.** :class:`FakeContext` stands in for a Playwright browser context:
  the login flow's logic is worth testing, and a real Chromium in a unit test is not.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import redaction

# Values shaped like the real thing: `g.a0` prefix, no delimiters, long enough that
# `register_secret`'s length floor accepts them.
FAKE_PSID = "g.a000fakePSIDvalue_0123456789abcdefghijklmnopqrstuvwxyz"
FAKE_PSIDTS = "sidts-CjIB3fakePSIDTSvalue_9876543210zyxwvutsrqponmlkjihg"
OTHER_PSID = "g.a000otherAccountPSID_abcdefghijklmnopqrstuvwxyz0123456"

#: Far-future expiry, so a fixture cookie is never dropped as expired.
FUTURE = float(int(time.time()) + 365 * 24 * 3600)
#: Long past, for the expired-cookie cases.
PAST = 1_000_000.0

_ENV_NAMES = (
    auth_paths.GEMINI_HOME_ENV,
    auth_paths.GEMINI_AUTH_STORAGE_ENV,
    auth_paths.GEMINI_AUTH_PROFILE_ENV,
    auth_paths.GEMINI_AUTH_SHARED_ENV,
    auth_paths.GEMINI_AUTH_WRITEBACK_ENV,
    auth_paths.GEMINI_COOKIE_PATH_ENV,
    auth_paths.GEMINI_SECURE_1PSID_ENV,
    auth_paths.GEMINI_SECURE_1PSIDTS_ENV,
    auth_paths.NOTEBOOKLM_HOME_ENV,
)


class IsolatedHome:
    """Context manager giving a test its own gemini-web + notebooklm homes.

    Use as ``with IsolatedHome() as home:``. On exit the temporary tree is removed and
    every auth environment variable is restored to what it was — including "was
    unset", which is the state that matters on a developer machine where a real
    ``GEMINI_SECURE_1PSID`` might be exported.
    """

    def __init__(self, **env: str) -> None:
        self._extra_env = env
        self._saved: dict[str, str | None] = {}
        self._tmp: tempfile.TemporaryDirectory | None = None
        self.root = Path()

    def __enter__(self) -> IsolatedHome:
        self._tmp = tempfile.TemporaryDirectory(prefix="gemini-auth-test-")
        self.root = Path(self._tmp.name)
        for name in _ENV_NAMES:
            self._saved[name] = os.environ.pop(name, None)
        os.environ[auth_paths.GEMINI_HOME_ENV] = str(self.gemini_home)
        os.environ[auth_paths.NOTEBOOKLM_HOME_ENV] = str(self.notebooklm_home)
        for name, value in self._extra_env.items():
            self._saved.setdefault(name, os.environ.get(name))
            os.environ[name] = value
        redaction.clear_registry()
        return self

    def __exit__(self, *exc_info: object) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        redaction.clear_registry()
        if self._tmp is not None:
            self._tmp.cleanup()

    # --- locations -----------------------------------------------------------

    @property
    def gemini_home(self) -> Path:
        return self.root / "gemini-home"

    @property
    def notebooklm_home(self) -> Path:
        return self.root / "notebooklm-home"

    def own_storage(self, profile: str = "default") -> Path:
        return self.gemini_home / "profiles" / profile / "storage_state.json"

    def shared_storage(self, profile: str = "default") -> Path:
        return self.notebooklm_home / "profiles" / profile / "storage_state.json"

    # --- fixtures ------------------------------------------------------------

    def write_storage(
        self,
        path: Path,
        *,
        psid: str | None = FAKE_PSID,
        psidts: str | None = FAKE_PSIDTS,
        extra_cookies: list[dict[str, Any]] | None = None,
        foreign: dict[str, Any] | None = None,
        expires: float = FUTURE,
    ) -> Path:
        """Write a storage state at ``path`` and return it.

        ``foreign`` puts another tool's top-level key in the document, which is what
        the "we must not clobber notebooklm" assertions check for afterwards.
        """
        cookies: list[dict[str, Any]] = []
        if psid:
            cookies.append(cookie_row("__Secure-1PSID", psid, expires=expires))
        if psidts:
            cookies.append(cookie_row("__Secure-1PSIDTS", psidts, expires=expires))
        cookies.extend(extra_cookies or [])
        document: dict[str, Any] = {"cookies": cookies, "origins": []}
        if foreign:
            document.update(foreign)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        # 0600, like `storage_state.save` writes it. A fixture with default permissions
        # makes `doctor` report a permissions problem the product never created.
        auth_paths.harden_file(path)
        return path


def cookie_row(
    name: str,
    value: str,
    *,
    domain: str = ".google.com",
    path: str = "/",
    expires: float = FUTURE,
) -> dict[str, Any]:
    """Return a Playwright-shaped cookie row."""
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "expires": expires,
        "httpOnly": True,
        "secure": True,
        "sameSite": "None",
    }


@dataclass
class FakePage:
    """Minimal Playwright page: records navigations, optionally fails them."""

    goto_calls: list[str] = field(default_factory=list)
    fail_goto: bool = False

    async def goto(self, url: str, **_kwargs: Any) -> None:
        self.goto_calls.append(url)
        if self.fail_goto:
            raise RuntimeError("net::ERR_ABORTED")


@dataclass
class FakeContext:
    """Minimal Playwright browser context.

    ``cookie_schedule`` is a list of cookie lists, returned one per poll: that is how
    a test expresses "signed out for two polls, then signed in" without any timing.
    The last entry repeats once exhausted.
    """

    cookie_schedule: list[list[dict[str, Any]]] = field(default_factory=lambda: [[]])
    pages: list[FakePage] = field(default_factory=list)
    closed: bool = False
    poll_count: int = 0
    fail_goto: bool = False

    async def cookies(self) -> list[dict[str, Any]]:
        index = min(self.poll_count, len(self.cookie_schedule) - 1)
        self.poll_count += 1
        return list(self.cookie_schedule[index])

    async def new_page(self) -> FakePage:
        page = FakePage(fail_goto=self.fail_goto)
        self.pages.append(page)
        return page

    async def close(self) -> None:
        self.closed = True


def fake_launcher(context: FakeContext):
    """Return a ``launcher`` callable yielding ``context``, as :func:`capture` expects."""

    @contextlib.asynccontextmanager
    async def _launcher(_plan: Any):
        try:
            yield context
        finally:
            await context.close()

    return _launcher


@dataclass
class FakeJarCookie:
    """A ``curl_cffi`` / ``http.cookiejar``-shaped cookie, for write-back tests."""

    name: str
    value: str
    expires: float | None = FUTURE
    domain: str = ".google.com"
    path: str = "/"


def no_sleep(_delay: float) -> Any:
    """Async no-op replacement for ``asyncio.sleep`` in polling loops."""

    async def _noop() -> None:
        return None

    return _noop()
