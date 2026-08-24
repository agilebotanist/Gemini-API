"""The security regression suite: a real-shaped cookie must not escape anywhere.

Every other module tests a component. This one tests the property the components exist
to provide, from the outside: put a known value in the session file, exercise the
surfaces a human or a log aggregator sees, and grep the result. If any future change
prints a cookie — a new status field, a debug line, a dataclass repr — one of these
fails.

The value is checked for in three forms, because a leak rarely arrives verbatim:
the value itself, its first 16 characters (truncated output), and its URL-quoted form.
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest
import urllib.parse

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import playwright_login as login
from gemini_webapi.auth import redaction, resolver
from gemini_webapi.auth import storage_state as store
from gemini_webapi.cli import main

from ._support import FAKE_PSID, FAKE_PSIDTS, FakeContext, IsolatedHome, cookie_row, fake_launcher

SIGNED_IN = [
    cookie_row("__Secure-1PSID", FAKE_PSID),
    cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS),
]


def leak_forms(value: str) -> list[str]:
    """Return the spellings a leaked value could plausibly take in output."""
    return [value, value[:16], urllib.parse.quote(value)]


class SecretLeakTestCase(unittest.TestCase):
    def assertNoSecret(self, text: str, *, label: str = "output") -> None:
        for secret in (FAKE_PSID, FAKE_PSIDTS):
            for form in leak_forms(secret):
                self.assertNotIn(
                    form,
                    text,
                    f"{label} leaked a credential ({redaction.fingerprint(secret)})",
                )


class TestCliSurfaces(SecretLeakTestCase):
    def _run(self, argv: list[str], home) -> str:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(argv)
        return out.getvalue() + err.getvalue()

    def test_auth_status_text_and_json(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage(), foreign={"notebooklm": {"a": 1}})
            self.assertNoSecret(self._run(["auth", "status"], home), label="auth status")
            payload = self._run(["auth", "status", "--json"], home)
            self.assertNoSecret(payload, label="auth status --json")
            json.loads(payload)  # still valid JSON after redaction

    def test_doctor(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            self.assertNoSecret(self._run(["doctor"], home), label="doctor")

    def test_logout(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            self.assertNoSecret(self._run(["logout", "--shared"], home), label="logout")

    def test_verbose_flag_does_not_widen_the_disclosure(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            self.assertNoSecret(
                self._run(["--verbose", "auth", "status"], home), label="verbose status"
            )

    def test_login_output(self):
        with IsolatedHome():
            plan = login.LoginPlan.build()
            context = FakeContext(cookie_schedule=[SIGNED_IN])
            messages: list[str] = []
            result = login.run_login(plan, launcher=fake_launcher(context), emit=messages.append)
            rendered = "\n".join(messages) + repr(result) + str(result.__dict__)
            self.assertNoSecret(rendered, label="login")


class TestObjectRepresentations(SecretLeakTestCase):
    def test_credentials(self):
        creds = resolver.Credentials(psid=FAKE_PSID, psidts=FAKE_PSIDTS, source="test")
        self.assertNoSecret(repr(creds) + str(creds) + json.dumps(creds.summary()))

    def test_storage_state_summary(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            state = store.load(path)
            self.assertNoSecret(json.dumps(state.summary()), label="StorageState.summary")

    def test_status_report(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            self.assertNoSecret(json.dumps(resolver.status()), label="resolver.status")

    def test_login_result_repr(self):
        result = login.LoginResult(
            status=login.STATUS_CAPTURED,
            storage_path=auth_paths.gemini_home() / "x.json",
            shared=False,
            psid=redaction.fingerprint(FAKE_PSID),
        )
        self.assertNoSecret(repr(result), label="LoginResult")

    def test_cookie_row_error(self):
        from gemini_webapi.auth.cookie_policy import CookieRowError, sanitize_row

        try:
            sanitize_row({"name": "__Secure-1PSID", "value": FAKE_PSID + "\r\n"})
        except CookieRowError as exc:
            self.assertNoSecret(str(exc) + repr(exc), label="CookieRowError")
        else:  # pragma: no cover
            self.fail("expected CookieRowError")


class TestLogSurfaces(SecretLeakTestCase):
    def test_package_logger_scrubs_registered_values(self):
        from loguru import logger as root_logger

        from gemini_webapi.utils.logger import logger

        with IsolatedHome() as home:
            store.load(home.write_storage(home.own_storage()))  # registers the values
            sink = io.StringIO()
            handler = root_logger.add(sink, level="DEBUG", format="{message}")
            try:
                logger.debug(f"cookie jar: {FAKE_PSID} / {FAKE_PSIDTS}")
                logger.warning(f"Cookie: __Secure-1PSID={FAKE_PSID}")
            finally:
                root_logger.remove(handler)
            self.assertNoSecret(sink.getvalue(), label="package logger")

    def test_a_traceback_carrying_a_cookie_is_scrubbable(self):
        # Third-party code raising with a cookie in the message is the leak path we
        # cannot prevent at the source, only scrub on the way out.
        with IsolatedHome() as home:
            store.load(home.write_storage(home.own_storage()))
            try:
                raise RuntimeError(f"401 for cookie {FAKE_PSID}")
            except RuntimeError as exc:
                self.assertNoSecret(redaction.scrub(str(exc)), label="scrubbed traceback")


class TestOnDiskFootprint(SecretLeakTestCase):
    def test_cache_filename_is_a_digest(self):
        with IsolatedHome():
            self.assertNoSecret(str(auth_paths.cookie_cache_path(FAKE_PSID)), label="cache path")

    def test_lock_and_temp_filenames_are_value_free(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            store.update_credentials(path, psid=FAKE_PSID, psidts="sidts-CjIBsomethingNew01")
            names = " ".join(p.name for p in path.parent.iterdir())
            self.assertNoSecret(names, label="directory listing")

    def test_no_temp_file_is_left_holding_a_credential(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            store.update_credentials(path, psid=FAKE_PSID, psidts="sidts-CjIBanotherValue02")
            self.assertEqual(list(path.parent.glob("*.tmp")), [])


class TestSourceDiscipline(SecretLeakTestCase):
    """A cheap structural check: no f-string prints a raw credential attribute."""

    def test_auth_modules_do_not_format_raw_values(self):
        import pathlib

        import gemini_webapi.auth as auth_pkg

        offenders = []
        for path in pathlib.Path(next(iter(auth_pkg.__path__))).glob("*.py"):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or "print(" in stripped:
                    continue
                for pattern in ("{psid}", "{psidts}", "{creds.psid}", '{value}"'):
                    if pattern in stripped and "fingerprint" not in stripped:
                        offenders.append(f"{path.name}:{number}: {stripped}")
        self.assertEqual(offenders, [], "raw credential interpolation found")


if __name__ == "__main__":
    unittest.main()
