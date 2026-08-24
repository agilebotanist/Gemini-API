"""Fingerprints and scrubbing — the mechanics of "a value is never printed"."""

from __future__ import annotations

import io
import unittest

from gemini_webapi.auth import redaction

from ._support import FAKE_PSID, FAKE_PSIDTS, IsolatedHome, cookie_row


class TestFingerprint(unittest.TestCase):
    def test_stable_prefixed_and_short(self):
        first = redaction.fingerprint(FAKE_PSID)
        self.assertEqual(first, redaction.fingerprint(FAKE_PSID))
        self.assertTrue(first.startswith("sha256:"))
        self.assertEqual(len(first), len("sha256:") + 8)

    def test_never_contains_the_value(self):
        self.assertNotIn(FAKE_PSID[:8], redaction.fingerprint(FAKE_PSID))

    def test_different_values_differ(self):
        self.assertNotEqual(redaction.fingerprint(FAKE_PSID), redaction.fingerprint(FAKE_PSIDTS))

    def test_absent_renders_as_dash(self):
        # Absence is a normal state for __Secure-1PSIDTS; it must not look like a
        # fingerprint, or "no cookie" reads as "some cookie".
        for empty in (None, ""):
            self.assertEqual(redaction.fingerprint(empty), "-")

    def test_accepts_bytes(self):
        self.assertEqual(
            redaction.fingerprint(FAKE_PSID),
            redaction.fingerprint(FAKE_PSID.encode()),
        )


class TestRegistry(unittest.TestCase):
    def setUp(self):
        redaction.clear_registry()

    def tearDown(self):
        redaction.clear_registry()

    def test_registered_value_is_scrubbed_anywhere_in_a_string(self):
        redaction.register_secret(FAKE_PSID)
        text = f"traceback: Cookie(value={FAKE_PSID!r}) at line 3"
        scrubbed = redaction.scrub(text)
        self.assertNotIn(FAKE_PSID, scrubbed)
        self.assertIn(redaction.fingerprint(FAKE_PSID), scrubbed)

    def test_short_values_are_not_registered(self):
        redaction.register_secret("abc")
        self.assertEqual(redaction.registered_secret_count(), 0)
        # ...and scrubbing does not mangle text containing them.
        self.assertEqual(redaction.scrub("abc def"), "abc def")

    def test_none_and_duplicates_are_ignored(self):
        redaction.register_secret(None, FAKE_PSID, FAKE_PSID)
        self.assertEqual(redaction.registered_secret_count(), 1)

    def test_longer_secret_wins_when_one_contains_another(self):
        inner = "sidts-CjIBshortoverlapvalue"
        outer = inner + "-extended-tail-0123456789"
        redaction.register_secret(inner, outer)
        scrubbed = redaction.scrub(f"value={outer}")
        self.assertNotIn(inner, scrubbed)
        self.assertIn(redaction.fingerprint(outer), scrubbed)


class TestStructuralScrubbing(unittest.TestCase):
    """Values this process never held still get scrubbed, by shape."""

    def setUp(self):
        redaction.clear_registry()

    def test_cookie_header_assignment(self):
        unseen = "g.a000neverRegisteredValue_zyxwvutsrqponmlkjihgfedcba98"
        scrubbed = redaction.scrub(f"Cookie: __Secure-1PSID={unseen}; NID=511=abcdefghij")
        self.assertNotIn(unseen, scrubbed)
        self.assertNotIn("511=abcdefghij", scrubbed)
        self.assertIn("__Secure-1PSID=<redacted:", scrubbed)

    def test_json_name_value_pair(self):
        unseen = "g.a000jsonShapedValue_0987654321abcdefghijklmnopqrstuv"
        scrubbed = redaction.scrub(f'{{"__Secure-1PSIDTS": "{unseen}"}}')
        self.assertNotIn(unseen, scrubbed)

    def test_bare_google_token(self):
        # A storage_state row prints `"name": "__Secure-1PSID"` and `"value": "g.a0…"`
        # as separate keys, so only the token's own shape can catch it.
        unseen = "g.a000bareTokenInATraceback_abcdefghijklmnopqrstuvwxyz01"
        scrubbed = redaction.scrub(f'{{"name": "__Secure-1PSID", "value": "{unseen}"}}')
        self.assertNotIn(unseen, scrubbed)

    def test_ordinary_text_is_untouched(self):
        text = "Initialized client, 3 models available, quota 42% used."
        self.assertEqual(redaction.scrub(text), text)

    def test_non_string_input_is_coerced(self):
        self.assertEqual(redaction.scrub(42), "42")
        self.assertEqual(redaction.scrub(None), "None")


class TestCookieSummary(unittest.TestCase):
    def test_summary_names_cookies_without_values(self):
        rows = [
            cookie_row("__Secure-1PSID", FAKE_PSID),
            cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS),
        ]
        summary = redaction.cookie_summary(rows)
        self.assertIn("__Secure-1PSID@.google.com=sha256:", summary)
        self.assertNotIn(FAKE_PSID, summary)
        self.assertNotIn(FAKE_PSIDTS, summary)

    def test_empty_is_explicit(self):
        self.assertEqual(redaction.cookie_summary([]), "(none)")

    def test_malformed_rows_are_skipped(self):
        self.assertEqual(redaction.cookie_summary([{"no_name": 1}]), "(none)")


class TestLoggerIntegration(unittest.TestCase):
    """The package logger scrubs by construction, not by call-site discipline."""

    def setUp(self):
        redaction.clear_registry()

    def tearDown(self):
        redaction.clear_registry()

    def test_secret_logged_through_the_package_logger_is_scrubbed(self):
        from loguru import logger as root_logger

        from gemini_webapi.utils.logger import logger

        redaction.register_secret(FAKE_PSID)
        sink = io.StringIO()
        handler_id = root_logger.add(sink, level="DEBUG", format="{message}")
        try:
            logger.debug(f"leaking {FAKE_PSID} by accident")
        finally:
            root_logger.remove(handler_id)

        captured = sink.getvalue()
        self.assertIn("leaking", captured)
        self.assertNotIn(FAKE_PSID, captured)
        self.assertIn(redaction.fingerprint(FAKE_PSID), captured)

    def test_scrub_record_is_defensive(self):
        # A patcher that raises would break all logging; it must swallow instead.
        class Hostile(dict):
            def __getitem__(self, key):
                raise RuntimeError("boom")

        redaction.scrub_record(Hostile())  # must not raise

    def test_storage_load_registers_values_so_later_logs_are_covered(self):
        from gemini_webapi.auth import storage_state

        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            storage_state.load(path)
            self.assertGreaterEqual(redaction.registered_secret_count(), 2)
            self.assertNotIn(FAKE_PSID, redaction.scrub(f"oops {FAKE_PSID}"))


if __name__ == "__main__":
    unittest.main()
