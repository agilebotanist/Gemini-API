"""Interactive (and headless-refresh) Google login through Playwright.

The problem this solves: Gemini's web endpoints authenticate with Google session
cookies, and the supported ways to obtain them were "read another browser's cookie
database" (``browser-cookie3``: fragile, blocked by Chrome's app-bound encryption on
Windows, needs the browser closed on some platforms) or "paste ``__Secure-1PSID`` out
of devtools by hand". Neither survives a session expiry without a human, which is what
made the tool unreliable in automation (ADR-0002).

So: launch a real Chromium against a **persistent profile**, let the person sign in
once, and capture the cookies from the browser context. Afterwards the profile itself
holds the Google session, so a *headless* re-run can refresh the rotating token with no
interaction at all — which is the mode that keeps a long-lived agent working.

The profile directory and the resulting ``storage_state.json`` are, by default, the
ones ``notebooklm`` already uses (ADR-0003): one login, two tools.

Design notes:

* **Everything Playwright is behind one seam.** :func:`capture` takes a ``launcher``
  callable; the default builds a real Chromium context, and tests inject a fake. That
  is what makes the login flow unit-testable without a browser, and the flow — poll,
  filter, merge, report — is where the bugs actually live.
* **No value ever leaves.** Progress output names cookies and prints fingerprints.
  The capture path calls :func:`register_secret` before anything can log, so even a
  Playwright traceback carrying a cookie is scrubbed.
* **A capture never destroys.** Cookies are merged into whatever the storage state
  already holds; nothing else in it is touched.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gemini_webapi.exceptions import AuthError

from . import cookie_policy as policy
from . import storage_state as store
from .paths import StorageTarget, gemini_home, profile_name, secure_mkdir, storage_target
from .redaction import fingerprint, register_secret

#: Where a signed-in session is confirmed. The app URL redirects to the account
#: chooser when there is no session, so reaching it signed-out is the normal start of
#: an interactive login rather than an error.
GEMINI_APP_URL = "https://gemini.google.com/app"
#: Where an interactive `--switch-account` run starts. Landing on the Gemini app when
#: the profile already has a session shows that session's chat list, with the account
#: switcher several clicks away; Google's own add-account entry point is the page the
#: user is actually looking for, and it continues to Gemini once they are done.
GOOGLE_ADD_SESSION_URL = (
    "https://accounts.google.com/AddSession?continue=https%3A%2F%2Fgemini.google.com%2Fapp"
)

#: Default patience for a human completing a Google login: password, 2FA, consent
#: screens, occasionally a device prompt. Shorter defaults produce "it timed out while
#: I was reading the SMS" bug reports.
DEFAULT_LOGIN_TIMEOUT = 300.0
#: A headless refresh either finds a session in the profile or does not; there is no
#: human to wait for.
DEFAULT_REFRESH_TIMEOUT = 45.0

STATUS_CAPTURED = "captured"
STATUS_UNCHANGED = "unchanged"
STATUS_TIMEOUT = "timeout"
STATUS_NO_SESSION = "no-session"
#: The browser's session belongs to a different account than the stored one, and the
#: run was not told it may switch. Nothing is written (ADR-0009).
STATUS_MISMATCH = "mismatch"
#: The capture was probed against Gemini and came back unauthenticated. Nothing is
#: written — this is the case that motivated verification in the first place (ADR-0009).
STATUS_UNVERIFIED = "unverified"


class LoginError(AuthError):
    """Login could not be completed. The message is user-facing and value-free."""


@dataclass(frozen=True)
class LoginPlan:
    """Everything a login run needs, resolved before any browser starts.

    Separating the plan from the execution keeps the "which file, which profile,
    shared or not" decisions testable on their own — they are the part a user gets
    wrong, and the part that decides whose credentials get written.
    """

    storage_path: Path
    browser_profile_dir: Path
    shared: bool
    headless: bool = False
    timeout: float = DEFAULT_LOGIN_TIMEOUT
    channel: str | None = None
    target_url: str = GEMINI_APP_URL
    poll_interval: float = 1.5
    note: str | None = None
    #: May a capture replace a *different* session than the one already stored? Off by
    #: default: a refresh that silently switches accounts, or overwrites a working
    #: credential with a stale one from the same profile, is the failure ADR-0009
    #: describes. ``gemini-web login --switch-account`` turns it on deliberately.
    allow_switch: bool = False
    #: Probe a session-changing capture against Gemini before persisting it.
    verify: bool = True

    @classmethod
    def build(
        cls,
        *,
        profile: str | None = None,
        headless: bool = False,
        timeout: float | None = None,
        channel: str | None = None,
        allow_shared: bool | None = None,
        storage_path: Path | None = None,
        browser_profile_dir: Path | None = None,
        allow_switch: bool = False,
        verify: bool = True,
    ) -> LoginPlan:
        """Resolve a plan from CLI-shaped options.

        One rule deserves calling out: when the resolved target is NotebookLM's
        profile but its ``storage_state.json`` does **not** exist yet, the capture is
        redirected to our own profile. Gemini needs two cookies; NotebookLM needs a
        dozen. Creating *their* file with *our* two would leave a document that looks
        like a session and is not one, for a tool that never asked us to write it.
        Joining an existing session is sharing; fabricating one is not (ADR-0003).
        """
        target: StorageTarget = storage_target(profile, allow_shared=allow_shared)
        note = None
        if storage_path is None and target.shared and not target.path.exists():
            own = gemini_home() / "profiles" / profile_name(profile) / "storage_state.json"
            note = (
                f"NotebookLM's profile has no session file yet; writing our own at {own} "
                "instead of creating a partial one in its directory."
            )
            target = StorageTarget(own, source="own", shared=False)

        resolved_storage = (storage_path or target.path).expanduser()
        resolved_browser = (
            browser_profile_dir.expanduser()
            if browser_profile_dir is not None
            else target.browser_profile_dir
        )
        return cls(
            storage_path=resolved_storage,
            browser_profile_dir=resolved_browser,
            shared=target.shared,
            headless=headless,
            target_url=GOOGLE_ADD_SESSION_URL
            if (allow_switch and not headless)
            else GEMINI_APP_URL,
            timeout=timeout
            if timeout is not None
            else (DEFAULT_REFRESH_TIMEOUT if headless else DEFAULT_LOGIN_TIMEOUT),
            channel=channel,
            note=note,
            allow_switch=allow_switch,
            verify=verify,
        )


@dataclass(frozen=True)
class LoginResult:
    """Outcome of a login run. Every field is safe to print.

    ``changed`` names the cookies whose value the storage state did not already hold,
    which is how ``STATUS_UNCHANGED`` is distinguished from ``STATUS_CAPTURED``: a
    headless refresh that finds the same token did nothing, and saying so is more
    useful than reporting success.
    """

    status: str
    storage_path: Path
    shared: bool
    changed: list[str] = field(default_factory=list)
    cookie_names: list[str] = field(default_factory=list)
    psid: str = "-"
    psidts: str = "-"
    previous_psid: str = "-"
    message: str = ""
    #: ``True`` verified live, ``False`` verified and rejected, ``None`` not probed
    #: (a same-session refresh needs no probe) or the probe could not reach Gemini.
    verified: bool | None = None
    #: What the probe reported, e.g. ``"AVAILABLE"`` / ``"UNAUTHENTICATED"``.
    verify_status: str = ""

    @property
    def ok(self) -> bool:
        return self.status in {STATUS_CAPTURED, STATUS_UNCHANGED}

    @property
    def switched_account(self) -> bool:
        """Whether the capture replaced a different Google session than the stored one."""
        return self.previous_psid not in {"-", self.psid}


def ensure_playwright() -> None:
    """Raise :class:`LoginError` with actionable instructions if Playwright is absent."""
    try:
        import playwright  # noqa: F401
        from playwright.async_api import async_playwright  # noqa: F401
    except ImportError as exc:
        raise LoginError(
            "Playwright is required for `gemini-web login`.\n"
            '  pip install "gemini-webapi[playwright]"\n'
            "  python -m playwright install chromium"
        ) from exc


def run_on_suitable_loop(coro: Any) -> Any:
    """Run ``coro`` on an event loop that can spawn Playwright's browser subprocess.

    Playwright talks to the browser over a subprocess pipe, which the Windows
    *selector* loop cannot create — a host that installed the selector policy (some web
    frameworks do) would make login fail with ``NotImplementedError``. Naming the loop
    factory for this one run fixes that without mutating the global event-loop policy,
    which is both rude to the host application and deprecated as of Python 3.14.
    """
    if sys.platform == "win32":
        with asyncio.Runner(loop_factory=asyncio.ProactorEventLoop) as runner:
            return runner.run(coro)
    return asyncio.run(coro)


@contextlib.asynccontextmanager
async def _default_launcher(plan: LoginPlan):
    """Yield a real persistent Chromium context for ``plan``.

    A *persistent* context (rather than ``launch()`` + a fresh context) is the whole
    point: the profile directory keeps the Google session after the browser closes,
    which is what makes the later headless refresh possible without another
    interactive login.
    """
    from playwright.async_api import async_playwright

    secure_mkdir(plan.browser_profile_dir)
    async with async_playwright() as driver:
        kwargs: dict[str, Any] = {
            "user_data_dir": str(plan.browser_profile_dir),
            "headless": plan.headless,
            # Keep the automation obvious to Google and stable across runs: no
            # extensions, no first-run wizard, default viewport.
            "args": ["--no-first-run", "--no-default-browser-check"],
        }
        if plan.channel:
            kwargs["channel"] = plan.channel
        context = await driver.chromium.launch_persistent_context(**kwargs)
        try:
            yield context
        finally:
            with contextlib.suppress(Exception):
                await context.close()


async def capture(
    plan: LoginPlan,
    *,
    launcher: Callable[[LoginPlan], Any] | None = None,
    emit: Callable[[str], None] | None = None,
    sleep: Callable[[float], Any] = asyncio.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    verifier: Callable[[str, str | None], Any] | None = None,
) -> LoginResult:
    """Run one login/refresh cycle and persist the cookies, if they earn it.

    Polls the browser context rather than waiting on a page selector. Google's sign-in
    flow crosses several origins and layouts and A/B-tests its DOM; the cookie jar is
    the only signal that means "authenticated" in every variant, and it is the signal
    we actually need.

    Three outcomes are *not* a write, and each has its own status:

    * the poll never saw a session (``timeout`` / ``no-session``);
    * the session found is a different one than the file already holds, and the plan
      does not allow switching (``mismatch``);
    * the session is new *and* a live probe says it is not authenticated
      (``unverified``) — the case a stale cookie in a real browser profile produced,
      see ADR-0009.

    ``verifier`` is the probe seam: it defaults to
    :func:`gemini_webapi.auth.verify.verify_credentials`, and tests pass a fake so the
    flow stays offline.
    """
    emit = emit or (lambda _message: None)
    launcher = launcher or _default_launcher

    if plan.note:
        emit(plan.note)

    previous = store.load(plan.storage_path, strict=False)
    previous_psid_fp = fingerprint(previous.psid)

    deadline = monotonic() + max(plan.timeout, 0.0)
    rows: list[dict[str, Any]] = []
    announced = False
    baseline: str | None = None
    wait_for_change = False
    window_closed = False

    async with launcher(plan) as context:
        page = await _open_page(context, plan, emit)
        if page is None and not plan.headless:
            emit("Could not open a browser page; polling the profile's cookies instead.")

        first_poll = True
        while True:
            observed = await _read_cookies(context)
            if observed is None:
                # The window is gone. Whatever the last successful read saw is all we
                # will ever have, so stop rather than spin until the timeout.
                window_closed = True
                break
            rows = policy.filter_cookies(observed)
            psid, psidts = policy.credentials_from_rows(rows)

            if first_poll:
                first_poll = False
                baseline = psid
                # A persistent profile usually *already* holds a session cookie, so
                # "any PSID is present" cannot mean "the human is done" in an
                # interactive run: the window would close before they could type
                # anything. When the session already there is not the one we want -
                # they asked to switch accounts, or it disagrees with the stored one -
                # the signal to wait for is the cookie *changing*.
                # Only when the user explicitly asked to switch. A plain `login` that
                # finds a session it may not use fails fast with the mismatch message
                # instead of holding a browser window open for five minutes.
                wait_for_change = not plan.headless and psid is not None and plan.allow_switch
                if wait_for_change:
                    emit(
                        "The browser profile already holds a session "
                        f"({fingerprint(psid)}). Sign in - or use Google's account "
                        "switcher to add the account you want - in the window that just "
                        "opened.\n"
                        "  The window closes by itself once a different session appears. "
                        "Closing it yourself cancels without writing anything."
                    )
                    announced = True

            if psid and not (wait_for_change and psid == baseline):
                register_secret(psid, psidts)
                break
            if monotonic() >= deadline:
                break
            if not announced and not plan.headless:
                emit(
                    "Waiting for the Google sign-in to complete in the browser window... "
                    "(the window closes by itself once the session is captured)"
                )
                announced = True
            await sleep(plan.poll_interval)

    psid, psidts = policy.credentials_from_rows(rows)
    if wait_for_change and psid == baseline:
        # Timed out, or the window was closed, without the session changing.
        return LoginResult(
            status=STATUS_NO_SESSION if window_closed else STATUS_TIMEOUT,
            storage_path=plan.storage_path,
            shared=plan.shared,
            previous_psid=previous_psid_fp,
            message=(
                "The browser window closed before a new session appeared. Nothing was written."
                if window_closed
                else f"Timed out after {plan.timeout:g}s: the browser profile's session did "
                f"not change ({fingerprint(baseline)}). Nothing was written.\n"
                "  Sign in fully in the window before it times out, or raise --timeout."
            ),
        )
    if not psid:
        if plan.headless:
            return LoginResult(
                status=STATUS_NO_SESSION,
                storage_path=plan.storage_path,
                shared=plan.shared,
                previous_psid=previous_psid_fp,
                message=(
                    "No signed-in Google session in the browser profile at "
                    f"{plan.browser_profile_dir}. Run `gemini-web login` (without --headless) once."
                ),
            )
        return LoginResult(
            status=STATUS_TIMEOUT,
            storage_path=plan.storage_path,
            shared=plan.shared,
            previous_psid=previous_psid_fp,
            message=(
                f"Timed out after {plan.timeout:g}s without a Google session. Nothing was written."
            ),
        )

    names = sorted(row["name"] for row in rows)
    session_changes = bool(previous.psid) and previous.psid != psid

    def outcome(status: str, message: str, **extra: Any) -> LoginResult:
        return LoginResult(
            status=status,
            storage_path=plan.storage_path,
            shared=plan.shared,
            cookie_names=names,
            psid=fingerprint(psid),
            psidts=fingerprint(psidts),
            previous_psid=previous_psid_fp,
            message=message,
            **extra,
        )

    # A different session than the stored one is never written by accident. It may be
    # another Google account, or - the case seen in practice - a stale `.google.com`
    # cookie sitting in a browser profile whose live session was established some other
    # way. Both would replace a working credential with a broken one (ADR-0009).
    if session_changes and not plan.allow_switch:
        return outcome(
            STATUS_MISMATCH,
            "The browser profile's session "
            f"({fingerprint(psid)}) is not the one stored in {plan.storage_path} "
            f"({previous_psid_fp}). Nothing was written.\n"
            "  To sign in and replace it - another account, or the same one after the "
            "stored session expired:\n"
            "      gemini-web login --switch-account\n"
            "    That opens Google's account chooser and waits for you to finish; the new "
            "session is checked against Gemini before it is stored.\n"
            "  If you did not mean to change anything, the stored session is still the "
            "good one - a browser profile can hold a stale cookie for the same account.",
        )

    verified: bool | None = None
    verify_status = ""
    if session_changes and plan.verify:
        emit("Verifying the captured session with Gemini before storing it...")
        probe = (verifier or _default_verifier)(psid, psidts)
        if inspect.isawaitable(probe):
            probe = await probe
        verified, verify_status = probe.ok, probe.status
        if probe.ok is False:
            return outcome(
                STATUS_UNVERIFIED,
                f"The captured session is not authenticated ({probe.status}: {probe.detail}). "
                "Nothing was written - the stored session was left alone.\n"
                "  Sign in again in the browser window:  gemini-web login\n"
                "  To store it anyway:                   gemini-web login --switch-account --no-verify",
                verified=False,
                verify_status=probe.status,
            )
        if probe.ok is None:
            # Unknown is not a verdict. Refuse the overwrite rather than gamble a
            # working credential on a network hiccup.
            return outcome(
                STATUS_UNVERIFIED,
                f"{probe.detail} Nothing was written, because this capture would have "
                "replaced a different stored session.\n"
                "  Retry when the network is back, or force it with --no-verify.",
                verified=None,
                verify_status=probe.status,
            )
        emit(f"Verified: {probe.status}.")

    expires = _expiry_for(rows, policy.PSIDTS) or _expiry_for(rows, policy.PSID)
    changed = store.update_credentials(
        plan.storage_path,
        psid=psid,
        psidts=psidts,
        expires=expires,
        # Already gated above: either the session is unchanged, or the caller asked for
        # a switch and (unless waived) the new session was proven live.
        require_matching_psid=False,
    )
    return outcome(
        STATUS_CAPTURED if changed else STATUS_UNCHANGED,
        "",
        changed=changed,
        verified=verified,
        verify_status=verify_status,
    )


def _default_verifier(psid: str, psidts: str | None) -> Any:
    """Probe a captured session against Gemini. Imported lazily; see :mod:`.verify`.

    Returns the coroutine, which :func:`capture` awaits. The import is deferred because
    verification reaches into ``gemini_webapi.client``, and this module sits below it.
    """
    from .verify import averify_credentials

    return averify_credentials(psid, psidts)


async def _open_page(context: Any, plan: LoginPlan, emit: Callable[[str], None]) -> Any:
    """Bring up the Gemini app in ``context``, tolerating navigation failures.

    A failed ``goto`` is not fatal. The persistent profile may already hold a session,
    in which case the cookie poll succeeds regardless of whether this particular
    navigation did — and in headless refresh mode the navigation is only there to make
    Google re-issue the rotating cookie.
    """
    try:
        pages = list(getattr(context, "pages", []) or [])
        page = pages[0] if pages else await context.new_page()
    except Exception:  # pragma: no cover - context died before a page existed
        return None
    try:
        await page.goto(plan.target_url, wait_until="domcontentloaded")
    except Exception as exc:
        emit(f"Navigation to the Gemini app did not complete ({type(exc).__name__}); continuing.")
    return page


async def _read_cookies(context: Any) -> Iterable[Any] | None:
    """Return the context's cookies, or ``None`` if the browser is gone.

    The distinction matters: an empty jar means "not signed in yet, keep waiting",
    while a failed read means the human closed the window, and waiting out the full
    timeout on a browser that no longer exists is just a five-minute hang.
    """
    try:
        cookies = await context.cookies()
    except Exception:
        return None
    return cookies or []


def _expiry_for(rows: Iterable[dict[str, Any]], name: str) -> float | None:
    for row in rows:
        if row.get("name") == name:
            expires = row.get("expires")
            if isinstance(expires, (int, float)) and expires > 0:
                return float(expires)
    return None


def run_login(
    plan: LoginPlan,
    *,
    launcher: Callable[[LoginPlan], Any] | None = None,
    emit: Callable[[str], None] | None = None,
    verifier: Callable[[str, str | None], Any] | None = None,
) -> LoginResult:
    """Synchronous entry point used by the CLI.

    Owns the two environment concerns the async core should not care about: the
    Windows event-loop policy, and Playwright's own presence.
    """
    if launcher is None:
        ensure_playwright()
    return run_on_suitable_loop(capture(plan, launcher=launcher, emit=emit, verifier=verifier))


def purge_legacy_cache(paths: Iterable[Path]) -> list[str]:
    """Delete pre-fork cache files whose names embedded the session cookie.

    Returns the names it removed. Called from ``gemini-web login`` and
    ``gemini-web auth purge``: the moment a fresh session is captured is the natural time
    to drop the file that leaked the previous one's identity in a shared temp
    directory (ADR-0005).
    """
    removed = []
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            continue
        removed.append(path.name)
    return removed
