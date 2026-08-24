"""Proving a captured credential actually works, before it replaces a working one.

This module exists because of a live failure, not a hypothesis (ADR-0009). A headless
refresh against a browser profile that NotebookLM had established captured a
``__Secure-1PSID`` that *looked* fine — right cookie name, right domain, far-future
expiry — and authenticated as a **guest**. The profile's ``.google.com`` cookie was
stale; the working session in the session file had been minted through a different
path. Writing the capture over it replaced a good credential with a useless one.

So: a capture that would change which session is stored has to be *verified* first,
and verification means asking Gemini. There is no offline test for "is this cookie
live" — that is precisely what a bearer token means.

Two details make this safe to run mid-login:

* **The probe writes nothing.** ``GeminiClient.close()`` persists cookies through the
  same paths a real run does — the cache and the storage-state write-back. Both are
  disabled for the duration of the probe, so an unverified credential cannot reach
  disk by way of the check that was supposed to gate it.
* **A network failure is not a verdict.** It returns ``ok=None`` (unknown), and the
  caller treats unknown as "do not overwrite", never as "invalid".
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from dataclasses import dataclass

from .paths import GEMINI_AUTH_WRITEBACK_ENV, GEMINI_COOKIE_PATH_ENV
from .redaction import fingerprint

#: How long to give the probe. It is one init handshake; a slow network should not
#: stall a login for minutes, and a timeout degrades to "unknown", not "invalid".
DEFAULT_VERIFY_TIMEOUT = 60.0


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a live credential probe.

    ``ok`` is deliberately three-valued: ``True`` (the session is authenticated),
    ``False`` (Gemini answered, and the session is not), ``None`` (we could not find
    out). Collapsing ``None`` into ``False`` would turn an offline laptop into "your
    credentials are invalid", and collapsing it into ``True`` would defeat the point.
    """

    ok: bool | None
    status: str
    detail: str
    psid: str = "-"

    @property
    def authenticated(self) -> bool:
        return self.ok is True

    @property
    def unknown(self) -> bool:
        return self.ok is None


async def averify_credentials(
    psid: str,
    psidts: str | None,
    *,
    timeout: float = DEFAULT_VERIFY_TIMEOUT,
    proxy: str | None = None,
) -> VerifyResult:
    """Ask Gemini whether ``psid`` / ``psidts`` is a usable session.

    Runs the package's own init handshake — the same code path a real request uses, so
    "verified" means what the caller thinks it means — with cookie persistence
    suppressed. Returns a :class:`VerifyResult`; never raises.

    This is the async form, because its one production caller
    (:func:`gemini_webapi.auth.playwright_login.capture`) is already inside an event
    loop and ``asyncio.run`` from there would raise.
    """
    with _persistence_suppressed():
        try:
            status_name, description, authenticated = await _probe(
                psid, psidts, timeout=timeout, proxy=proxy
            )
        except Exception as exc:  # network down, endpoint changed, cancelled probe
            return VerifyResult(
                ok=None,
                status="unknown",
                detail=f"Could not reach Gemini to verify ({type(exc).__name__}).",
                psid=fingerprint(psid),
            )

    return VerifyResult(
        ok=authenticated,
        status=status_name,
        detail=description,
        psid=fingerprint(psid),
    )


def verify_credentials(
    psid: str,
    psidts: str | None,
    *,
    timeout: float = DEFAULT_VERIFY_TIMEOUT,
    proxy: str | None = None,
) -> VerifyResult:
    """Synchronous :func:`averify_credentials`, for callers outside an event loop."""
    return asyncio.run(averify_credentials(psid, psidts, timeout=timeout, proxy=proxy))


async def _probe(
    psid: str,
    psidts: str | None,
    *,
    timeout: float,
    proxy: str | None,
) -> tuple[str, str, bool]:
    """Initialise a throwaway client and report the account status it observed."""
    # Imported here, not at module scope: `gemini_webapi.client` imports `utils`, which
    # imports this package. A deferred import keeps that cycle from existing at all.
    from gemini_webapi import GeminiClient
    from gemini_webapi.constants import AccountStatus

    client = GeminiClient(psid, psidts or "", proxy=proxy)
    try:
        await client.init(timeout=timeout, auto_refresh=False, auto_close=False)
        status = client.account_status
    finally:
        await client.close()

    return status.name, status.description, status != AccountStatus.UNAUTHENTICATED


class _persistence_suppressed:  # noqa: N801 - a context manager used as a verb
    """Disable cookie persistence for the duration of a probe.

    ``GeminiClient.close()`` saves cookies: to the rotation cache, and — through
    ``save_cookies`` — back to the (possibly shared) session file. During verification
    that is exactly backwards: the write is what we are trying to gate. Redirecting the
    cache to a throwaway directory and switching write-back off closes both routes,
    and the environment is restored afterwards even if the probe raises.
    """

    def __init__(self) -> None:
        self._saved: dict[str, str | None] = {}
        self._tmp: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="gemini-verify-")
        for name, value in (
            (GEMINI_COOKIE_PATH_ENV, self._tmp.name),
            (GEMINI_AUTH_WRITEBACK_ENV, "0"),
        ):
            self._saved[name] = os.environ.get(name)
            os.environ[name] = value

    def __exit__(self, *exc_info: object) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None
