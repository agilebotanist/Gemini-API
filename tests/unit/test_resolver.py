"""The credential ladder and the status report."""

from __future__ import annotations

import json
import os
import unittest

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import resolver

from ._support import FAKE_PSID, FAKE_PSIDTS, OTHER_PSID, IsolatedHome

ENV_PSID = "g.a000fromTheEnvironment_abcdefghijklmnopqrstuvwxyz0123"


class TestLadder(unittest.TestCase):
    def test_explicit_beats_everything(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = ENV_PSID
            creds = resolver.resolve(psid=FAKE_PSID, psidts=FAKE_PSIDTS)
            self.assertEqual(creds.psid, FAKE_PSID)
            self.assertEqual(creds.source, resolver.SOURCE_EXPLICIT)

    def test_env_beats_storage(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = ENV_PSID
            creds = resolver.resolve()
            self.assertEqual(creds.psid, ENV_PSID)
            self.assertEqual(creds.source, resolver.SOURCE_ENV)

    def test_env_can_be_ignored(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = ENV_PSID
            creds = resolver.resolve(allow_env=False)
            self.assertEqual(creds.psid, FAKE_PSID)

    def test_storage_used_when_nothing_else_is_set(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            creds = resolver.resolve()
            self.assertEqual(creds.psid, FAKE_PSID)
            self.assertEqual(creds.source, resolver.SOURCE_STORAGE_OWN)
            self.assertEqual(creds.storage_path, home.own_storage())

    def test_shared_source_is_labelled_as_such(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            self.assertEqual(resolver.resolve().source, resolver.SOURCE_STORAGE_SHARED)

    def test_explicit_storage_env_is_labelled_separately(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.root / "custom.json")
            os.environ[auth_paths.GEMINI_AUTH_STORAGE_ENV] = str(path)
            self.assertEqual(resolver.resolve().source, resolver.SOURCE_STORAGE_ENV)

    def test_nothing_anywhere_returns_none(self):
        with IsolatedHome():
            self.assertIsNone(resolver.resolve())

    def test_empty_env_value_is_not_a_credential(self):
        with IsolatedHome():
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = "   "
            self.assertIsNone(resolver.resolve())

    def test_psidts_env_is_optional(self):
        with IsolatedHome():
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = ENV_PSID
            self.assertIsNone(resolver.resolve().psidts)

    def test_corrupt_storage_is_skipped_in_lenient_mode(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("{{{", encoding="utf-8")
            self.assertIsNone(resolver.storage_credentials())
            with self.assertRaises(Exception):
                resolver.storage_credentials(strict=True)


class TestCredentialsObject(unittest.TestCase):
    def test_repr_and_str_are_redacted(self):
        # A dataclass repr in a traceback or a pytest diff would print the cookie.
        creds = resolver.Credentials(psid=FAKE_PSID, psidts=FAKE_PSIDTS, source="test")
        for rendered in (repr(creds), str(creds), f"{creds}"):
            self.assertNotIn(FAKE_PSID, rendered)
            self.assertNotIn(FAKE_PSIDTS, rendered)
            self.assertIn("sha256:", rendered)

    def test_as_dict_carries_real_values_for_the_http_client(self):
        creds = resolver.Credentials(psid=FAKE_PSID, psidts=FAKE_PSIDTS, source="test")
        self.assertEqual(creds.as_dict()["__Secure-1PSID"], FAKE_PSID)

    def test_as_dict_omits_an_absent_psidts(self):
        creds = resolver.Credentials(psid=FAKE_PSID, psidts=None, source="test")
        self.assertEqual(list(creds.as_dict()), ["__Secure-1PSID"])

    def test_summary_is_value_free(self):
        creds = resolver.Credentials(psid=FAKE_PSID, psidts=FAKE_PSIDTS, source="test")
        self.assertNotIn(FAKE_PSID, json.dumps(creds.summary()))


class TestStorageCookieRows(unittest.TestCase):
    def test_returns_sanitised_rows(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            rows = resolver.storage_cookie_rows()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["domain"], ".google.com")

    def test_empty_when_there_is_no_file(self):
        with IsolatedHome():
            self.assertEqual(resolver.storage_cookie_rows(), [])

    def test_never_raises(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("not json at all", encoding="utf-8")
            self.assertEqual(resolver.storage_cookie_rows(), [])


class TestStatus(unittest.TestCase):
    def test_reports_the_full_picture(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage(), foreign={"notebooklm": {"a": 1}})
            report = resolver.status()
            self.assertEqual(report["profile"], "default")
            self.assertEqual(report["storage_source"], "shared")
            self.assertTrue(report["storage_shared"])
            self.assertTrue(report["sharing_enabled"])
            self.assertTrue(report["writeback_enabled"])
            self.assertEqual(report["resolved"]["source"], resolver.SOURCE_STORAGE_SHARED)
            self.assertEqual(report["storage"]["foreign_keys"], ["notebooklm"])

    def test_is_json_serialisable_and_value_free(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            os.environ[auth_paths.GEMINI_SECURE_1PSIDTS_ENV] = FAKE_PSIDTS
            serialised = json.dumps(resolver.status(), sort_keys=True)
            self.assertNotIn(FAKE_PSID, serialised)
            self.assertNotIn(FAKE_PSIDTS, serialised)

    def test_reports_a_corrupt_file_instead_of_raising(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("}{", encoding="utf-8")
            report = resolver.status()
            self.assertIsNotNone(report["storage_error"])
            self.assertIsNone(report["resolved"])

    def test_no_session_reports_none_resolved(self):
        with IsolatedHome():
            self.assertIsNone(resolver.status()["resolved"])

    def test_env_credentials_are_flagged(self):
        with IsolatedHome():
            os.environ[auth_paths.GEMINI_SECURE_1PSID_ENV] = ENV_PSID
            self.assertTrue(resolver.status()["env_credentials"])

    def test_profile_argument_is_honoured(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage("work"), psid=OTHER_PSID)
            report = resolver.status("work")
            self.assertEqual(report["profile"], "work")
            self.assertIn("work", report["storage"]["path"])

    def test_playwright_availability_is_reported(self):
        available, note = resolver.playwright_available()
        self.assertIsInstance(available, bool)
        self.assertIsInstance(note, str)
        if not available:
            self.assertIn("pip install", note)


if __name__ == "__main__":
    unittest.main()
