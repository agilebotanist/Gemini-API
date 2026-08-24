"""The cookie allowlist and row sanitisation."""

from __future__ import annotations

import time
import unittest

from gemini_webapi.auth import cookie_policy as policy

from ._support import FAKE_PSID, FAKE_PSIDTS, FUTURE, PAST, cookie_row


class TestAllowlist(unittest.TestCase):
    def test_exactly_two_names_are_allowed(self):
        # Minimum privilege is the point (ADR-0004): a leak of what we hold should be
        # a Gemini session, not the whole Google account surface.
        self.assertEqual(
            policy.ALLOWED_COOKIE_NAMES,
            frozenset({"__Secure-1PSID", "__Secure-1PSIDTS"}),
        )

    def test_google_domain_spellings_both_accepted(self):
        for domain in (".google.com", "google.com", "GOOGLE.COM"):
            self.assertTrue(policy.is_allowed("__Secure-1PSID", domain), domain)

    def test_other_domains_and_names_rejected(self):
        self.assertFalse(policy.is_allowed("__Secure-1PSID", "accounts.google.com"))
        self.assertFalse(policy.is_allowed("__Secure-1PSID", "evil-google.com"))
        self.assertFalse(policy.is_allowed("SAPISID", ".google.com"))
        self.assertFalse(policy.is_allowed("__Secure-3PSID", ".google.com"))
        self.assertFalse(policy.is_allowed("__Secure-1PSID", None))


class TestSanitizeRow(unittest.TestCase):
    def test_normalises_a_complete_row(self):
        clean = policy.sanitize_row(cookie_row("__Secure-1PSID", FAKE_PSID))
        self.assertEqual(clean["name"], "__Secure-1PSID")
        self.assertEqual(clean["value"], FAKE_PSID)
        self.assertEqual(clean["path"], "/")
        self.assertIsInstance(clean["expires"], float)

    def test_fills_in_defaults(self):
        clean = policy.sanitize_row({"name": "__Secure-1PSID", "value": FAKE_PSID})
        self.assertEqual(clean["domain"], ".google.com")
        self.assertEqual(clean["path"], "/")
        self.assertEqual(clean["expires"], -1.0)
        self.assertTrue(clean["secure"])

    def test_rejects_non_mapping(self):
        for bad in ("string", 42, None, ["list"]):
            with self.assertRaises(policy.CookieRowError) as ctx:
                policy.sanitize_row(bad)
            self.assertEqual(ctx.exception.field, "row")

    def test_rejects_missing_name_and_empty_value(self):
        with self.assertRaises(policy.CookieRowError) as ctx:
            policy.sanitize_row({"value": FAKE_PSID})
        self.assertEqual(ctx.exception.field, "name")

        with self.assertRaises(policy.CookieRowError) as ctx:
            policy.sanitize_row({"name": "__Secure-1PSID", "value": ""})
        self.assertEqual(ctx.exception.field, "value")

    def test_missing_value_allowed_when_not_required(self):
        clean = policy.sanitize_row({"name": "__Secure-1PSID"}, require_value=False)
        self.assertEqual(clean["value"], "")

    def test_rejects_control_characters_in_the_value(self):
        # A newline in a cookie value is a header-injection primitive once it reaches
        # an HTTP client.
        for bad in ("a\r\nb", "a\nb", "a\x00b", "a;b", "a\tb"):
            with self.assertRaises(policy.CookieRowError) as ctx:
                policy.sanitize_row({"name": "__Secure-1PSID", "value": bad + FAKE_PSID})
            self.assertEqual(ctx.exception.field, "value")

    def test_error_message_never_contains_the_value(self):
        try:
            policy.sanitize_row({"name": "__Secure-1PSID", "value": FAKE_PSID + "\n"})
        except policy.CookieRowError as exc:
            self.assertNotIn(FAKE_PSID, str(exc))
        else:  # pragma: no cover
            self.fail("expected CookieRowError")

    def test_millisecond_expiry_is_converted_to_seconds(self):
        # Browsers and export extensions disagree about the unit; read as seconds a
        # millisecond stamp lands ~50,000 years out and disables every expiry check.
        millis = FUTURE * 1000
        clean = policy.sanitize_row(
            {"name": "__Secure-1PSID", "value": FAKE_PSID, "expires": millis}
        )
        self.assertAlmostEqual(clean["expires"], FUTURE, delta=1.0)

    def test_session_cookie_expiry_normalised_to_minus_one(self):
        for raw in (-1, 0, None, False):
            clean = policy.sanitize_row(
                {"name": "__Secure-1PSID", "value": FAKE_PSID, "expires": raw}
            )
            self.assertEqual(clean["expires"], -1.0, raw)

    def test_chrome_extension_expiration_date_key_is_read(self):
        clean = policy.sanitize_row(
            {"name": "__Secure-1PSID", "value": FAKE_PSID, "expirationDate": FUTURE}
        )
        self.assertAlmostEqual(clean["expires"], FUTURE, delta=1.0)

    def test_unparseable_expiry_is_an_error(self):
        with self.assertRaises(policy.CookieRowError) as ctx:
            policy.sanitize_row(
                {"name": "__Secure-1PSID", "value": FAKE_PSID, "expires": "next tuesday"}
            )
        self.assertEqual(ctx.exception.field, "expires")


class TestExpiry(unittest.TestCase):
    def test_session_cookies_never_expire(self):
        self.assertFalse(policy.is_expired({"expires": -1.0}))

    def test_past_expiry_detected(self):
        self.assertTrue(policy.is_expired({"expires": PAST}))

    def test_skew_treats_nearly_expired_as_gone(self):
        soon = time.time() + 10
        self.assertFalse(policy.is_expired({"expires": soon}))
        self.assertTrue(policy.is_expired({"expires": soon}, skew=60))


class TestFilterCookies(unittest.TestCase):
    def test_keeps_only_allowed_rows(self):
        rows = [
            cookie_row("__Secure-1PSID", FAKE_PSID),
            cookie_row("SAPISID", "irrelevant-but-sensitive-value"),
            cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS),
            cookie_row("__Secure-1PSID", "wrong-domain", domain="accounts.google.com"),
        ]
        kept = policy.filter_cookies(rows)
        self.assertEqual(
            sorted(row["name"] for row in kept),
            ["__Secure-1PSID", "__Secure-1PSIDTS"],
        )

    def test_last_observation_wins_for_the_same_identity(self):
        rows = [
            cookie_row("__Secure-1PSIDTS", "sidts-CjIBolderValueThatRotatedAway"),
            cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS),
        ]
        kept = policy.filter_cookies(rows)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["value"], FAKE_PSIDTS)

    def test_domain_dot_spelling_collapses_to_one_identity(self):
        rows = [
            cookie_row(
                "__Secure-1PSID", "g.a000firstSpellingValue_abcdefghijklmnop", domain="google.com"
            ),
            cookie_row("__Secure-1PSID", FAKE_PSID, domain=".google.com"),
        ]
        self.assertEqual(len(policy.filter_cookies(rows)), 1)

    def test_expired_rows_dropped_and_reported(self):
        seen = []
        kept = policy.filter_cookies(
            [cookie_row("__Secure-1PSID", FAKE_PSID, expires=PAST)],
            on_error=lambda field, reason: seen.append((field, reason)),
        )
        self.assertEqual(kept, [])
        self.assertEqual(seen[0][0], "expires")

    def test_expired_rows_kept_when_asked(self):
        kept = policy.filter_cookies(
            [cookie_row("__Secure-1PSID", FAKE_PSID, expires=PAST)], drop_expired=False
        )
        self.assertEqual(len(kept), 1)

    def test_one_bad_row_does_not_fail_the_batch(self):
        kept = policy.filter_cookies(
            ["not a row", {"name": "__Secure-1PSID"}, cookie_row("__Secure-1PSID", FAKE_PSID)]
        )
        self.assertEqual(len(kept), 1)

    def test_error_callback_gets_field_and_reason_only(self):
        problems = []
        policy.filter_cookies(
            [{"name": "__Secure-1PSID", "value": FAKE_PSID + "\n"}],
            on_error=lambda field, reason: problems.append((field, reason)),
        )
        self.assertEqual(problems[0][0], "value")
        self.assertNotIn(FAKE_PSID, problems[0][1])


class TestCredentialsFromRows(unittest.TestCase):
    def test_extracts_both(self):
        psid, psidts = policy.credentials_from_rows(
            [cookie_row("__Secure-1PSID", FAKE_PSID), cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS)]
        )
        self.assertEqual((psid, psidts), (FAKE_PSID, FAKE_PSIDTS))

    def test_psidts_may_be_absent(self):
        psid, psidts = policy.credentials_from_rows([cookie_row("__Secure-1PSID", FAKE_PSID)])
        self.assertEqual(psid, FAKE_PSID)
        self.assertIsNone(psidts)

    def test_furthest_expiry_wins_across_duplicates(self):
        # Multi-account profiles carry one row per account index; picking arbitrarily
        # is how a session authenticates as the wrong account.
        rows = [
            cookie_row(
                "__Secure-1PSID",
                "g.a000staleAccountValue_abcdefghijklmnopqrst",
                expires=FUTURE - 5000,
            ),
            cookie_row("__Secure-1PSID", FAKE_PSID, expires=FUTURE),
        ]
        psid, _ = policy.credentials_from_rows(rows)
        self.assertEqual(psid, FAKE_PSID)

    def test_ignores_other_names_and_empty_values(self):
        rows = [cookie_row("SAPISID", "x" * 40), cookie_row("__Secure-1PSID", "")]
        self.assertEqual(policy.credentials_from_rows(rows), (None, None))


if __name__ == "__main__":
    unittest.main()
