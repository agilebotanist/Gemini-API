"""The CLI's session commands: argument surface, routing, and exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import os
import unittest

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import storage_state as store
from gemini_webapi.cli import auth_commands, build_parser, main

from ._support import FAKE_PSID, FAKE_PSIDTS, IsolatedHome


@contextlib.contextmanager
def captured():
    """Capture stdout and stderr together, the way a user sees a terminal."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


class TestParser(unittest.TestCase):
    def test_session_commands_are_registered(self):
        parser = build_parser()
        for argv in (["login"], ["logout"], ["auth", "status"], ["auth", "purge"], ["doctor"]):
            args = parser.parse_args(argv)
            self.assertEqual(args.command, argv[0])

    def test_login_flags(self):
        args = build_parser().parse_args(
            ["login", "--headless", "--timeout", "12", "--channel", "chrome"]
        )
        self.assertTrue(args.headless)
        self.assertEqual(args.timeout, 12)
        self.assertEqual(args.channel, "chrome")

    def test_global_profile_and_sharing_flags(self):
        args = build_parser().parse_args(["--profile", "work", "--no-shared", "auth", "status"])
        self.assertEqual(args.profile, "work")
        self.assertTrue(args.no_shared)

    def test_upstream_commands_still_parse(self):
        args = build_parser().parse_args(["--model", "gemini-pro", "ask", "hello", "--no-stream"])
        self.assertEqual(args.command, "ask")
        self.assertEqual(args.prompt, "hello")
        self.assertTrue(args.no_stream)

    def test_status_json_flag(self):
        self.assertTrue(build_parser().parse_args(["auth", "status", "--json"]).json)


class TestProfilePinning(unittest.TestCase):
    def test_profile_flag_is_exported_for_the_whole_process(self):
        # Background rotation write-back resolves its own path, so the profile has to
        # be process state rather than an argument threaded through the client.
        with IsolatedHome():
            args = build_parser().parse_args(["--profile", "work", "auth", "status"])
            from gemini_webapi.cli.main import _apply_profile

            _apply_profile(args)
            self.assertEqual(os.environ[auth_paths.GEMINI_AUTH_PROFILE_ENV], "work")

    def test_no_shared_flag_is_exported(self):
        with IsolatedHome():
            from gemini_webapi.cli.main import _apply_profile

            _apply_profile(build_parser().parse_args(["--no-shared", "auth", "status"]))
            self.assertEqual(os.environ[auth_paths.GEMINI_AUTH_SHARED_ENV], "0")

    def test_bad_profile_exits_with_a_message(self):
        with IsolatedHome(), captured() as (out, _err):
            code = main(["--profile", "../escape", "auth", "status"])
            self.assertEqual(code, 2)
            self.assertIn("Invalid profile name", out.getvalue())


class TestAuthStatusCommand(unittest.TestCase):
    def test_reports_a_session(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage(), foreign={"notebooklm": {"a": 1}})
            with captured() as (out, _err):
                code = main(["auth", "status"])
            text = out.getvalue()
            self.assertEqual(code, auth_commands.EXIT_OK)
            self.assertIn("shared with notebooklm", text)
            self.assertIn("sha256:", text)
            self.assertNotIn(FAKE_PSID, text)

    def test_exit_code_two_when_there_is_no_session(self):
        with IsolatedHome(), captured() as (out, _err):
            code = main(["auth", "status"])
            self.assertEqual(code, auth_commands.EXIT_NO_SESSION)
            self.assertIn("gemini-web login", out.getvalue())

    def test_json_output_is_machine_readable_and_value_free(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            with captured() as (out, _err):
                code = main(["auth", "status", "--json"])
            payload = json.loads(out.getvalue())
            self.assertEqual(code, auth_commands.EXIT_OK)
            self.assertEqual(payload["profile"], "default")
            self.assertNotIn(FAKE_PSID, json.dumps(payload))

    def test_warns_about_environment_credentials(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = FAKE_PSID
            with captured() as (out, _err):
                main(["auth", "status"])
            self.assertIn("GEMINI_SECURE_1PSID is set", out.getvalue())


class TestDoctorCommand(unittest.TestCase):
    def test_clean_setup_passes(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            with captured() as (out, _err):
                code = main(["doctor"])
            text = out.getvalue()
            if code == auth_commands.EXIT_OK:
                self.assertIn("All checks passed", text)
            else:
                # The only legitimate failure in a temp home is a missing Playwright.
                self.assertIn("playwright", text.lower())

    def test_missing_session_is_reported_with_a_fix(self):
        with IsolatedHome(), captured() as (out, _err):
            code = main(["doctor"])
            self.assertEqual(code, auth_commands.EXIT_FAIL)
            self.assertIn("gemini-web login", out.getvalue())

    def test_shared_file_with_writeback_off_is_a_warning(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            os.environ[auth_paths.GEMINI_AUTH_WRITEBACK_ENV] = "0"
            with captured() as (out, _err):
                main(["doctor"])
            self.assertIn("invalidate notebooklm", out.getvalue())

    def test_legacy_cache_is_reported(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            legacy = auth_paths.legacy_cookie_cache_dir()
            legacy.mkdir(parents=True, exist_ok=True)
            marker = legacy / f".cached_cookies_{FAKE_PSID[:12]}unit-test.json"
            marker.write_text("[]", encoding="utf-8")
            try:
                with captured() as (out, _err):
                    main(["doctor"])
                self.assertIn("auth purge", out.getvalue())
            finally:
                marker.unlink(missing_ok=True)


class TestDoctorLiveCheck(unittest.TestCase):
    """`doctor --live` is the only check that can see a revoked session."""

    def _with_probe(self, probe):
        from gemini_webapi.auth import verify

        original = verify._probe
        verify._probe = probe
        self.addCleanup(lambda: setattr(verify, "_probe", original))

    def test_reports_a_working_session(self):
        async def probe(*_a, **_k):
            return "AVAILABLE", "Account is available.", True

        self._with_probe(probe)
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            with captured() as (out, _err):
                main(["doctor", "--live"])
            self.assertIn("live session", out.getvalue())
            self.assertIn("AVAILABLE", out.getvalue())

    def test_a_revoked_session_is_a_problem_with_a_fix(self):
        async def probe(*_a, **_k):
            return "UNAUTHENTICATED", "Session is not authenticated.", False

        self._with_probe(probe)
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            with captured() as (out, _err):
                code = main(["doctor", "--live"])
            self.assertEqual(code, auth_commands.EXIT_FAIL)
            self.assertIn("notebooklm login", out.getvalue())

    def test_an_unreachable_probe_is_only_a_warning(self):
        async def probe(*_a, **_k):
            raise ConnectionError("offline")

        self._with_probe(probe)
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            with captured() as (out, _err):
                main(["doctor", "--live"])
            self.assertIn("Could not reach Gemini", out.getvalue())

    def test_offline_doctor_never_probes(self):
        async def probe(*_a, **_k):  # pragma: no cover - must not run
            raise AssertionError("plain `doctor` must not touch the network")

        self._with_probe(probe)
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            with captured() as (out, _err):
                main(["doctor"])
            self.assertNotIn("live session", out.getvalue())


class TestLogoutCommand(unittest.TestCase):
    def test_removes_our_own_session_file_and_cache(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            cache = auth_paths.secure_mkdir(home.gemini_home / "cache")
            (cache / ".cached_cookies_deadbeef.json").write_text("[]", encoding="utf-8")
            with captured() as (out, _err):
                code = main(["logout"])
            self.assertEqual(code, auth_commands.EXIT_OK)
            self.assertFalse(path.exists())
            self.assertEqual(list(cache.glob("*.json")), [])
            self.assertIn("still", out.getvalue())  # the "Google session is still valid" note

    def test_leaves_a_shared_file_alone_by_default(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            with captured() as (out, _err):
                main(["logout"])
            self.assertTrue(path.exists())
            self.assertEqual(store.load(path).psid, FAKE_PSID)
            self.assertIn("--shared", out.getvalue())

    def test_shared_flag_strips_only_our_cookies(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage(), foreign={"notebooklm": {"a": 1}})
            with captured() as (_out, _err):
                main(["logout", "--shared"])
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["cookies"], [])
            self.assertIn("notebooklm", document)

    def test_nothing_to_remove_is_stated(self):
        with IsolatedHome(), captured() as (out, _err):
            main(["logout"])
            self.assertIn("Nothing to remove", out.getvalue())


class TestPurgeCommand(unittest.TestCase):
    def test_reports_a_clean_state(self):
        with IsolatedHome() as home:
            os.environ[auth_paths.GEMINI_COOKIE_PATH_ENV] = str(home.root / "cache")
            with captured() as (out, _err):
                code = main(["auth", "purge"])
            self.assertEqual(code, auth_commands.EXIT_OK)
            self.assertIn("No legacy cache files", out.getvalue())

    def test_removes_legacy_files(self):
        with IsolatedHome():
            legacy = auth_paths.legacy_cookie_cache_dir()
            legacy.mkdir(parents=True, exist_ok=True)
            marker = legacy / ".cached_cookies_purge-unit-test.json"
            marker.write_text("[]", encoding="utf-8")
            try:
                with captured() as (out, _err):
                    code = main(["auth", "purge"])
                self.assertEqual(code, auth_commands.EXIT_OK)
                self.assertIn("Removed", out.getvalue())
                self.assertFalse(marker.exists())
            finally:
                marker.unlink(missing_ok=True)


class TestDispatch(unittest.TestCase):
    def test_unknown_auth_subcommand_fails_with_usage(self):
        with IsolatedHome(), captured() as (_out, err):
            args = build_parser().parse_args(["auth"])
            code = auth_commands.dispatch(args)
            self.assertEqual(code, auth_commands.EXIT_FAIL)
            self.assertIn("Usage: gemini-web auth", err.getvalue())

    def test_non_session_commands_are_not_handled_here(self):
        args = build_parser().parse_args(["ask", "hi"])
        self.assertIsNone(auth_commands.dispatch(args))

    def test_no_command_prints_help(self):
        with IsolatedHome(), captured() as (out, _err):
            self.assertEqual(main([]), 1)
            self.assertIn("usage: gemini-web", out.getvalue())


class TestEnvironmentSummary(unittest.TestCase):
    def test_paths_are_shown_and_cookies_are_fingerprinted(self):
        with IsolatedHome() as home:
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = FAKE_PSID
            os.environ[auth_paths.GEMINI_SECURE_1PSIDTS_ENV] = FAKE_PSIDTS
            summary = auth_commands.environment_summary()
            self.assertEqual(summary[auth_paths.GEMINI_HOME_ENV], str(home.gemini_home))
            self.assertTrue(summary[auth_paths.GEMINI_SECURE_1PSID_ENV].startswith("sha256:"))
            self.assertNotIn(FAKE_PSID, json.dumps(summary))


class TestClientCredentialWiring(unittest.TestCase):
    def test_missing_session_tells_the_user_to_log_in(self):
        from gemini_webapi.cli.main import _build_client

        with IsolatedHome():
            args = build_parser().parse_args(["ask", "hi"])
            with self.assertRaises(SystemExit) as ctx:
                _build_client(args)
            self.assertIn("gemini-web login", str(ctx.exception))

    def test_stored_session_is_used(self):
        from gemini_webapi.cli.main import _build_client

        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            args = build_parser().parse_args(["ask", "hi"])
            client, _cookies = _build_client(args)
            names = {cookie.name for cookie in client.cookies.jar}
            self.assertIn("__Secure-1PSID", names)


if __name__ == "__main__":
    unittest.main()
