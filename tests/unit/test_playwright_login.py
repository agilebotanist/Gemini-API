"""The login flow, driven against a fake browser context.

What is worth testing here is not Playwright — it is the decisions around it: which
file gets written, when a capture counts as a change, what happens when the sign-in
never completes, and whether an account switch is reported. A real Chromium would test
none of that any better and could not run in CI.
"""

from __future__ import annotations

import asyncio
import sys
import unittest

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import playwright_login as login
from gemini_webapi.auth import storage_state as store
from gemini_webapi.auth.verify import VerifyResult

from ._support import (
    FAKE_PSID,
    FAKE_PSIDTS,
    FUTURE,
    OTHER_PSID,
    FakeContext,
    IsolatedHome,
    cookie_row,
    fake_launcher,
)

SIGNED_IN = [
    cookie_row("__Secure-1PSID", FAKE_PSID),
    cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS),
    cookie_row("SAPISID", "a-cookie-we-must-not-store"),
]

#: What a persistent profile looks like *before* the human switches accounts: it already
#: holds a session, which is why "any PSID present" cannot mean "sign-in finished".
SIGNED_IN_AS_SOMEONE_ELSE = [
    cookie_row("__Secure-1PSID", OTHER_PSID),
    cookie_row("__Secure-1PSIDTS", "sidts-CjIBtheOtherAccountsToken1"),
]

#: An interactive switch: the profile starts on one session and lands on another.
SWITCHING = [SIGNED_IN_AS_SOMEONE_ELSE, SIGNED_IN_AS_SOMEONE_ELSE, SIGNED_IN]


def instant(_delay):
    """Replacement for `asyncio.sleep` so polling loops run at full speed."""
    return asyncio.sleep(0)


def run(coro):
    return asyncio.run(coro)


class TestLoginPlan(unittest.TestCase):
    def test_uses_the_shared_file_when_it_exists(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            plan = login.LoginPlan.build()
            self.assertEqual(plan.storage_path, home.shared_storage())
            self.assertTrue(plan.shared)
            self.assertIsNone(plan.note)

    def test_falls_back_to_our_own_file_when_notebooklms_is_absent(self):
        # Creating notebooklm's session file with only Gemini's two cookies would hand
        # it a document that looks like a session and is not one (ADR-0003).
        with IsolatedHome() as home:
            home.shared_storage().parent.mkdir(parents=True)
            plan = login.LoginPlan.build()
            self.assertEqual(plan.storage_path, home.own_storage())
            self.assertFalse(plan.shared)
            self.assertIn("partial", plan.note)

    def test_own_profile_when_no_notebooklm_tree_at_all(self):
        with IsolatedHome() as home:
            plan = login.LoginPlan.build()
            self.assertEqual(plan.storage_path, home.own_storage())
            self.assertIsNone(plan.note)

    def test_browser_profile_sits_beside_the_session_file(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            plan = login.LoginPlan.build()
            self.assertEqual(
                plan.browser_profile_dir, home.shared_storage().parent / "browser_profile"
            )

    def test_overrides_are_respected(self):
        with IsolatedHome() as home:
            plan = login.LoginPlan.build(
                profile="work",
                headless=True,
                channel="chrome",
                browser_profile_dir=home.root / "custom-profile",
            )
            self.assertEqual(plan.storage_path, home.own_storage("work"))
            self.assertTrue(plan.headless)
            self.assertEqual(plan.channel, "chrome")
            self.assertEqual(plan.browser_profile_dir, home.root / "custom-profile")

    def test_default_timeouts_differ_by_mode(self):
        with IsolatedHome():
            self.assertEqual(login.LoginPlan.build().timeout, login.DEFAULT_LOGIN_TIMEOUT)
            self.assertEqual(
                login.LoginPlan.build(headless=True).timeout, login.DEFAULT_REFRESH_TIMEOUT
            )
            self.assertEqual(login.LoginPlan.build(timeout=12).timeout, 12)

    def test_no_shared_flag_forces_our_own_profile(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            plan = login.LoginPlan.build(allow_shared=False)
            self.assertEqual(plan.storage_path, home.own_storage())

    def test_invalid_profile_is_rejected(self):
        with IsolatedHome():
            with self.assertRaises(ValueError):
                login.LoginPlan.build(profile="../escape")


def verifier_returning(ok, status):
    """Return a fake verifier reporting ``ok`` / ``status`` without any network."""

    def _verify(_psid, _psidts):
        return VerifyResult(ok=ok, status=status, detail=f"fake probe: {status}")

    return _verify


class TestCapture(unittest.TestCase):
    def _plan(self, _home, **kwargs):
        return login.LoginPlan.build(**kwargs)

    def test_captures_a_session_and_writes_only_our_cookies(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = run(login.capture(plan, launcher=fake_launcher(context)))

            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertTrue(result.ok)
            self.assertEqual(result.cookie_names, ["__Secure-1PSID", "__Secure-1PSIDTS"])
            saved = store.load(plan.storage_path)
            self.assertEqual(saved.psid, FAKE_PSID)
            self.assertEqual(
                [row["name"] for row in saved.document["cookies"]],
                ["__Secure-1PSID", "__Secure-1PSIDTS"],
            )
            self.assertTrue(context.closed)

    def test_waits_through_signed_out_polls(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[[], [], SIGNED_IN])
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=lambda _d: asyncio.sleep(0),
                )
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertEqual(context.poll_count, 3)

    def test_reports_unchanged_when_the_token_is_the_same(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = run(login.capture(plan, launcher=fake_launcher(context)))
            self.assertEqual(result.status, login.STATUS_UNCHANGED)
            self.assertTrue(result.ok)
            self.assertEqual(result.changed, [])

    def test_reports_a_rotated_token_as_captured(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psidts="sidts-CjIBpreviousValue00")
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = run(login.capture(plan, launcher=fake_launcher(context)))
            self.assertEqual(result.changed, ["__Secure-1PSIDTS"])

    def test_a_different_session_is_refused_by_default(self):
        # The failure this rule exists for: a browser profile holding a stale
        # `.google.com` cookie silently replacing a working stored session (ADR-0009).
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = run(login.capture(plan, launcher=fake_launcher(context)))
            self.assertEqual(result.status, login.STATUS_MISMATCH)
            self.assertFalse(result.ok)
            self.assertEqual(result.changed, [])
            self.assertIn("--switch-account", result.message)
            self.assertEqual(store.load(plan.storage_path).psid, OTHER_PSID)

    def test_account_switch_is_written_when_allowed_and_verified(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True)
            context = FakeContext(cookie_schedule=SWITCHING)
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=instant,
                    verifier=verifier_returning(True, "AVAILABLE"),
                )
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertTrue(result.switched_account)
            self.assertTrue(result.verified)
            self.assertIn("__Secure-1PSID", result.changed)
            self.assertEqual(store.load(plan.storage_path).psid, FAKE_PSID)

    def test_an_unauthenticated_capture_is_not_written(self):
        # Exactly the live failure: the capture looks structurally perfect and is a
        # guest session. The stored credential must survive it.
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True)
            context = FakeContext(cookie_schedule=SWITCHING)
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=instant,
                    verifier=verifier_returning(False, "UNAUTHENTICATED"),
                )
            )
            self.assertEqual(result.status, login.STATUS_UNVERIFIED)
            self.assertFalse(result.ok)
            self.assertIs(result.verified, False)
            self.assertEqual(store.load(plan.storage_path).psid, OTHER_PSID)
            self.assertIn("not authenticated", result.message)

    def test_an_unreachable_probe_does_not_overwrite(self):
        # Unknown is not a verdict: a network hiccup must not cost a working session.
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True)
            context = FakeContext(cookie_schedule=SWITCHING)
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=instant,
                    verifier=verifier_returning(None, "unknown"),
                )
            )
            self.assertEqual(result.status, login.STATUS_UNVERIFIED)
            self.assertEqual(store.load(plan.storage_path).psid, OTHER_PSID)
            self.assertIn("--no-verify", result.message)

    def test_verification_can_be_waived(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True, verify=False)
            context = FakeContext(cookie_schedule=SWITCHING)
            calls: list[str] = []

            def refusing_verifier(psid, psidts):  # pragma: no cover - must not run
                calls.append(psid)
                raise AssertionError("verification should have been skipped")

            result = run(
                login.capture(
                    plan, launcher=fake_launcher(context), sleep=instant, verifier=refusing_verifier
                )
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertEqual(calls, [])
            self.assertIsNone(result.verified)

    def test_a_same_session_refresh_is_never_probed(self):
        # The common case - only the rotating token moved - must not cost a network
        # round trip, and cannot be a "switch".
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psidts="sidts-CjIBpreviousRotation1")
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])

            def refusing_verifier(psid, psidts):  # pragma: no cover - must not run
                raise AssertionError("a same-session refresh must not be probed")

            result = run(
                login.capture(plan, launcher=fake_launcher(context), verifier=refusing_verifier)
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertEqual(result.changed, ["__Secure-1PSIDTS"])
            self.assertFalse(result.switched_account)

    def test_first_login_into_an_empty_file_needs_no_probe(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])

            def refusing_verifier(psid, psidts):  # pragma: no cover - must not run
                raise AssertionError("nothing was at risk; no probe expected")

            result = run(
                login.capture(plan, launcher=fake_launcher(context), verifier=refusing_verifier)
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)

    def test_switch_waits_for_the_session_to_actually_change(self):
        # The bug this closes: a persistent profile already holds a PSID, so accepting
        # "any PSID" closed the window on the first poll and the human never got to
        # sign in. With --switch-account the signal is the cookie *changing*.
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True)
            context = FakeContext(cookie_schedule=SWITCHING)
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=instant,
                    verifier=verifier_returning(True, "AVAILABLE"),
                )
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertGreaterEqual(context.poll_count, 3)  # it did not stop at the baseline
            self.assertEqual(store.load(plan.storage_path).psid, FAKE_PSID)

    def test_switch_that_never_changes_times_out_without_writing(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True)
            context = FakeContext(cookie_schedule=[SIGNED_IN_AS_SOMEONE_ELSE])
            clock = iter([0.0, 0.0, 999.0])
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=instant,
                    monotonic=lambda: next(clock, 999.0),
                )
            )
            self.assertEqual(result.status, login.STATUS_TIMEOUT)
            self.assertIn("did not change", result.message)
            self.assertEqual(store.load(plan.storage_path).psid, OTHER_PSID)

    def test_closing_the_window_stops_immediately(self):
        # A closed browser is not "keep polling for five minutes".
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True)
            context = FakeContext(cookie_schedule=[SIGNED_IN_AS_SOMEONE_ELSE], die_after=2)
            result = run(login.capture(plan, launcher=fake_launcher(context), sleep=instant))
            self.assertEqual(result.status, login.STATUS_NO_SESSION)
            self.assertIn("closed", result.message)
            self.assertEqual(store.load(plan.storage_path).psid, OTHER_PSID)

    def test_switch_starts_on_googles_add_account_page(self):
        with IsolatedHome() as home:
            plan = self._plan(home, allow_switch=True)
            self.assertEqual(plan.target_url, login.GOOGLE_ADD_SESSION_URL)
            self.assertEqual(self._plan(home).target_url, login.GEMINI_APP_URL)
            # Headless has no human to click an account chooser.
            self.assertEqual(
                self._plan(home, allow_switch=True, headless=True).target_url,
                login.GEMINI_APP_URL,
            )

    def test_headless_never_waits_for_a_change(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            plan = self._plan(home, allow_switch=True, headless=True)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=instant,
                    verifier=verifier_returning(True, "AVAILABLE"),
                )
            )
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertEqual(context.poll_count, 1)

    def test_timeout_writes_nothing(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[[]])
            clock = iter([0.0, 0.0, 999.0, 999.0])
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=lambda _d: asyncio.sleep(0),
                    monotonic=lambda: next(clock, 999.0),
                )
            )
            self.assertEqual(result.status, login.STATUS_TIMEOUT)
            self.assertFalse(result.ok)
            self.assertIn("Nothing was written", result.message)
            self.assertFalse(plan.storage_path.exists())

    def test_headless_without_a_session_says_to_log_in_interactively(self):
        with IsolatedHome() as home:
            plan = self._plan(home, headless=True)
            context = FakeContext(cookie_schedule=[[]])
            clock = iter([0.0, 0.0, 999.0])
            result = run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    sleep=lambda _d: asyncio.sleep(0),
                    monotonic=lambda: next(clock, 999.0),
                )
            )
            self.assertEqual(result.status, login.STATUS_NO_SESSION)
            self.assertIn("without --headless", result.message)

    def test_navigation_failure_does_not_prevent_a_capture(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN], fail_goto=True)
            messages: list[str] = []
            result = run(login.capture(plan, launcher=fake_launcher(context), emit=messages.append))
            self.assertEqual(result.status, login.STATUS_CAPTURED)
            self.assertTrue(any("Navigation" in m for m in messages))

    def test_the_app_url_is_visited(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            run(login.capture(plan, launcher=fake_launcher(context)))
            self.assertEqual(context.pages[0].goto_calls, [login.GEMINI_APP_URL])

    def test_expiry_is_persisted_from_the_captured_cookie(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(
                cookie_schedule=[[cookie_row("__Secure-1PSID", FAKE_PSID, expires=FUTURE)]]
            )
            run(login.capture(plan, launcher=fake_launcher(context)))
            rows = {row["name"]: row for row in store.load(plan.storage_path).cookies}
            self.assertEqual(rows["__Secure-1PSID"]["expires"], FUTURE)

    def test_emitted_messages_never_contain_a_cookie_value(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[[], SIGNED_IN])
            messages: list[str] = []
            run(
                login.capture(
                    plan,
                    launcher=fake_launcher(context),
                    emit=messages.append,
                    sleep=lambda _d: asyncio.sleep(0),
                )
            )
            joined = "\n".join(messages)
            self.assertNotIn(FAKE_PSID, joined)
            self.assertNotIn(FAKE_PSIDTS, joined)

    def test_result_fields_are_fingerprints(self):
        with IsolatedHome() as home:
            plan = self._plan(home)
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = run(login.capture(plan, launcher=fake_launcher(context)))
            self.assertTrue(result.psid.startswith("sha256:"))
            self.assertNotIn(FAKE_PSID, repr(result))

    def test_plan_note_is_emitted(self):
        with IsolatedHome() as home:
            home.shared_storage().parent.mkdir(parents=True)
            plan = login.LoginPlan.build()
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            messages: list[str] = []
            run(login.capture(plan, launcher=fake_launcher(context), emit=messages.append))
            self.assertTrue(any("partial" in m for m in messages))


class TestRunLogin(unittest.TestCase):
    def test_sync_wrapper_runs_the_flow(self):
        with IsolatedHome():
            plan = login.LoginPlan.build()
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            result = login.run_login(plan, launcher=fake_launcher(context))
            self.assertEqual(result.status, login.STATUS_CAPTURED)

    def test_runs_on_a_loop_that_supports_subprocesses(self):
        # On Windows that means the proactor loop; asserting the loop *type* is what
        # catches a regression to `asyncio.run` under a host's selector policy.
        async def probe():
            return type(asyncio.get_running_loop()).__name__

        name = login.run_on_suitable_loop(probe())
        if sys.platform == "win32":
            self.assertEqual(name, "ProactorEventLoop")
        else:
            self.assertTrue(name.endswith("EventLoop"))


class TestPlaywrightAvailability(unittest.TestCase):
    def test_missing_playwright_produces_actionable_instructions(self):
        import builtins

        real_import = builtins.__import__

        def fail_playwright(name, *args, **kwargs):
            if name.startswith("playwright"):
                raise ImportError("no playwright")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = fail_playwright
        try:
            with self.assertRaises(login.LoginError) as ctx:
                login.ensure_playwright()
        finally:
            builtins.__import__ = real_import
        message = str(ctx.exception)
        self.assertIn("pip install", message)
        self.assertIn("playwright install chromium", message)


class TestPurgeLegacyCache(unittest.TestCase):
    def test_removes_files_and_reports_names(self):
        with IsolatedHome() as home:
            directory = auth_paths.secure_mkdir(home.root / "legacy")
            first = directory / f".cached_cookies_{FAKE_PSID}.json"
            first.write_text("[]", encoding="utf-8")
            removed = login.purge_legacy_cache([first, directory / "absent.json"])
            self.assertEqual(removed, [first.name])
            self.assertFalse(first.exists())


if __name__ == "__main__":
    unittest.main()
