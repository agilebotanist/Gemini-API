"""Write-back: keeping the shared session file current after a rotation."""

from __future__ import annotations

import os
import unittest

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import storage_state as store
from gemini_webapi.auth import writeback

from ._support import (
    FAKE_PSID,
    FAKE_PSIDTS,
    FUTURE,
    OTHER_PSID,
    FakeJarCookie,
    IsolatedHome,
)

ROTATED = "sidts-CjIBfreshlyRotatedValue_0123456789abcdefghijklmn"


class TestSyncCredentials(unittest.TestCase):
    def test_updates_an_existing_session_file(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            changed = writeback.sync_credentials(FAKE_PSID, ROTATED, path=path)
            self.assertEqual(changed, ["__Secure-1PSIDTS"])
            self.assertEqual(store.load(path).psidts, ROTATED)

    def test_no_op_when_nothing_changed(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            self.assertEqual(writeback.sync_credentials(FAKE_PSID, FAKE_PSIDTS, path=path), [])

    def test_does_not_create_a_missing_file(self):
        # A rotation must not invent a credential store, least of all in another
        # tool's directory.
        with IsolatedHome() as home:
            path = home.shared_storage()
            self.assertEqual(writeback.sync_credentials(FAKE_PSID, ROTATED, path=path), [])
            self.assertFalse(path.exists())

    def test_skips_a_different_session(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage(), psid=OTHER_PSID)
            self.assertEqual(writeback.sync_credentials(FAKE_PSID, ROTATED, path=path), [])
            self.assertEqual(store.load(path).psid, OTHER_PSID)

    def test_disabled_by_environment(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            os.environ[auth_paths.GEMINI_AUTH_WRITEBACK_ENV] = "0"
            self.assertEqual(writeback.sync_credentials(FAKE_PSID, ROTATED, path=path), [])
            self.assertEqual(store.load(path).psidts, FAKE_PSIDTS)

    def test_requires_a_psid(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            self.assertEqual(writeback.sync_credentials(None, ROTATED, path=path), [])

    def test_resolves_the_target_when_no_path_is_given(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            changed = writeback.sync_credentials(FAKE_PSID, ROTATED)
            self.assertEqual(changed, ["__Secure-1PSIDTS"])
            self.assertEqual(store.load(home.shared_storage()).psidts, ROTATED)

    def test_never_raises_on_a_broken_target(self):
        with IsolatedHome() as home:
            # A directory where a file is expected: the write must fail silently.
            path = home.shared_storage()
            path.mkdir(parents=True)
            self.assertEqual(writeback.sync_credentials(FAKE_PSID, ROTATED, path=path), [])


class TestSyncFromJar(unittest.TestCase):
    def test_extracts_only_the_two_cookies_we_own(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            jar = [
                FakeJarCookie("SAPISID", "should-be-ignored-entirely"),
                FakeJarCookie("__Secure-1PSID", FAKE_PSID),
                FakeJarCookie("__Secure-1PSIDTS", ROTATED, expires=FUTURE),
            ]
            changed = writeback.sync_from_jar(jar)
            self.assertEqual(changed, ["__Secure-1PSIDTS"])
            document = store.load(path).document
            self.assertNotIn("SAPISID", [row["name"] for row in document["cookies"]])

    def test_ignores_malformed_entries(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            jar = [
                object(),
                FakeJarCookie("__Secure-1PSID", FAKE_PSID),
                FakeJarCookie("__Secure-1PSIDTS", ""),
            ]
            self.assertEqual(writeback.sync_from_jar(jar), [])

    def test_empty_jar_is_a_no_op(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            self.assertEqual(writeback.sync_from_jar([]), [])

    def test_expiry_from_the_jar_is_carried_over(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            writeback.sync_from_jar(
                [
                    FakeJarCookie("__Secure-1PSID", FAKE_PSID),
                    FakeJarCookie("__Secure-1PSIDTS", ROTATED, expires=FUTURE),
                ]
            )
            rows = {row["name"]: row for row in store.load(path).cookies}
            self.assertEqual(rows["__Secure-1PSIDTS"]["expires"], FUTURE)


class TestDescribe(unittest.TestCase):
    def test_reports_names_and_a_fingerprint_only(self):
        line = writeback.describe(["__Secure-1PSIDTS"], ROTATED)
        self.assertIn("__Secure-1PSIDTS", line)
        self.assertIn("sha256:", line)
        self.assertNotIn(ROTATED, line)

    def test_says_so_when_nothing_changed(self):
        self.assertIn("already current", writeback.describe([]))


class TestRotationIntegration(unittest.TestCase):
    """`save_cookies` is the single choke point; it must reach the storage state."""

    def test_save_cookies_writes_cache_and_storage_state(self):
        from curl_cffi.requests import Cookies

        from gemini_webapi.utils.rotate_1psidts import save_cookies

        with IsolatedHome() as home:
            path = home.write_storage(home.shared_storage())
            jar = Cookies()
            jar.set("__Secure-1PSID", FAKE_PSID, domain=".google.com", secure=True)
            jar.set("__Secure-1PSIDTS", ROTATED, domain=".google.com", secure=True)

            save_cookies(jar)

            self.assertEqual(store.load(path).psidts, ROTATED)
            cache_files = list((home.gemini_home / "cache").glob(".cached_cookies_*.json"))
            self.assertEqual(len(cache_files), 1)
            self.assertNotIn(FAKE_PSID, cache_files[0].name)


if __name__ == "__main__":
    unittest.main()
