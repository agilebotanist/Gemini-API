"""Path resolution: the ladder, the profile rules, and the two security invariants."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

from gemini_webapi.auth import paths

from ._support import FAKE_PSID, IsolatedHome


class TestHomes(unittest.TestCase):
    def test_gemini_home_defaults_under_user_home(self):
        with IsolatedHome() as home:
            del os.environ[paths.GEMINI_HOME_ENV]
            self.assertEqual(paths.gemini_home(), Path.home() / ".gemini-webapi")
            os.environ[paths.GEMINI_HOME_ENV] = str(home.gemini_home)

    def test_gemini_home_honours_env(self):
        with IsolatedHome() as home:
            self.assertEqual(paths.gemini_home(), home.gemini_home)

    def test_notebooklm_home_matches_notebooklm_default(self):
        with IsolatedHome() as home:
            del os.environ[paths.NOTEBOOKLM_HOME_ENV]
            self.assertEqual(paths.notebooklm_home(), Path.home() / ".notebooklm")
            os.environ[paths.NOTEBOOKLM_HOME_ENV] = str(home.notebooklm_home)

    def test_env_flag_parsing(self):
        with IsolatedHome():
            for value, expected in (
                ("0", False),
                ("false", False),
                ("FALSE", False),
                ("no", False),
                ("off", False),
                ("", False),
                ("1", True),
                ("yes", True),
                ("anything", True),
            ):
                os.environ["GEMINI_TEST_FLAG"] = value
                self.assertIs(paths.env_flag("GEMINI_TEST_FLAG", default=True), expected, value)
            del os.environ["GEMINI_TEST_FLAG"]
            self.assertTrue(paths.env_flag("GEMINI_TEST_FLAG", default=True))
            self.assertFalse(paths.env_flag("GEMINI_TEST_FLAG", default=False))


class TestProfileName(unittest.TestCase):
    def test_precedence(self):
        with IsolatedHome() as home:
            os.environ[paths.GEMINI_AUTH_PROFILE_ENV] = "from-env"
            self.assertEqual(paths.profile_name(), "from-env")
            self.assertEqual(paths.profile_name("explicit"), "explicit")
            del os.environ[paths.GEMINI_AUTH_PROFILE_ENV]
            self.assertEqual(paths.profile_name(), "default")
            self.assertTrue(home.root.exists())

    def test_blank_falls_back_to_default(self):
        with IsolatedHome():
            self.assertEqual(paths.profile_name("   "), "default")

    def test_traversal_is_rejected_not_sanitised(self):
        # A rewritten name would read one file and write another; refusing is the only
        # safe answer.
        with IsolatedHome():
            for bad in ("..", ".", "a/b", "a\\b", "../../etc"):
                with self.assertRaises(ValueError, msg=bad):
                    paths.profile_name(bad)


class TestStorageTargetLadder(unittest.TestCase):
    def test_env_wins_over_everything(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            explicit = home.root / "explicit.json"
            os.environ[paths.GEMINI_AUTH_STORAGE_ENV] = str(explicit)
            target = paths.storage_target()
            self.assertEqual(target.path, explicit)
            self.assertEqual(target.source, "env")
            self.assertFalse(target.shared)

    def test_shared_used_when_notebooklm_profile_exists(self):
        with IsolatedHome() as home:
            home.shared_storage().parent.mkdir(parents=True)
            target = paths.storage_target()
            self.assertEqual(target.path, home.shared_storage())
            self.assertEqual(target.source, "shared")
            self.assertTrue(target.shared)

    def test_own_profile_when_no_notebooklm_tree(self):
        with IsolatedHome() as home:
            target = paths.storage_target()
            self.assertEqual(target.path, home.own_storage())
            self.assertEqual(target.source, "own")
            self.assertFalse(target.shared)

    def test_sharing_can_be_disabled_by_env_or_argument(self):
        with IsolatedHome() as home:
            home.shared_storage().parent.mkdir(parents=True)

            os.environ[paths.GEMINI_AUTH_SHARED_ENV] = "0"
            self.assertEqual(paths.storage_target().path, home.own_storage())

            del os.environ[paths.GEMINI_AUTH_SHARED_ENV]
            self.assertEqual(paths.storage_target(allow_shared=False).path, home.own_storage())
            self.assertEqual(paths.storage_target(allow_shared=True).path, home.shared_storage())

    def test_profile_selects_a_sibling_directory(self):
        with IsolatedHome() as home:
            target = paths.storage_target("work")
            self.assertEqual(target.path, home.own_storage("work"))
            self.assertEqual(target.path.parent.name, "work")

    def test_browser_profile_sits_beside_the_storage_state(self):
        with IsolatedHome() as home:
            home.shared_storage().parent.mkdir(parents=True)
            target = paths.storage_target()
            self.assertEqual(
                target.browser_profile_dir,
                home.shared_storage().parent / "browser_profile",
            )


class TestLockPath(unittest.TestCase):
    def test_matches_notebooklms_derivation_exactly(self):
        # This literal is a cross-tool contract, not a style choice: notebooklm
        # derives `.<name>.lock` and two different names mean no mutual exclusion.
        storage = Path("/tmp/profiles/default/storage_state.json")
        self.assertEqual(
            paths.storage_state_lock_path(storage).name,
            ".storage_state.json.lock",
        )
        self.assertEqual(paths.storage_state_lock_path(storage).parent, storage.parent)

    @unittest.skipIf(
        not Path.home().joinpath(".notebooklm").exists(),
        "no local notebooklm install to compare against",
    )
    def test_agrees_with_installed_notebooklm_if_present(self):
        try:
            from notebooklm._auth.paths import _storage_state_lock_path
        except Exception:  # pragma: no cover - notebooklm not importable
            self.skipTest("notebooklm not importable")
        storage = Path.home() / ".notebooklm" / "profiles" / "default" / "storage_state.json"
        self.assertEqual(
            paths.storage_state_lock_path(storage),
            _storage_state_lock_path(storage),
        )


class TestCookieCache(unittest.TestCase):
    def test_filename_never_contains_the_cookie_value(self):
        # The pre-fork bug: the raw __Secure-1PSID was the filename, in a shared temp
        # directory. No file mode can fix a leak that lives in the name (ADR-0005).
        with IsolatedHome():
            path = paths.cookie_cache_path(FAKE_PSID)
            self.assertNotIn(FAKE_PSID, str(path))
            self.assertNotIn(FAKE_PSID[:20], str(path))
            self.assertTrue(path.name.startswith(".cached_cookies_"))
            self.assertTrue(path.name.endswith(".json"))

    def test_digest_is_stable_and_hex(self):
        first = paths.cache_digest(FAKE_PSID)
        self.assertEqual(first, paths.cache_digest(FAKE_PSID))
        self.assertEqual(len(first), 32)
        int(first, 16)  # raises if not hex
        self.assertNotEqual(first, paths.cache_digest(FAKE_PSID + "x"))

    def test_cache_dir_defaults_under_the_auth_home_not_temp(self):
        with IsolatedHome() as home:
            self.assertEqual(paths.cookie_cache_dir(), home.gemini_home / "cache")
            # The point of the move: not the shared temp directory other users can list.
            self.assertNotEqual(paths.cookie_cache_dir(), paths.legacy_cookie_cache_dir())

    def test_legacy_override_still_honoured(self):
        with IsolatedHome() as home:
            os.environ[paths.GEMINI_COOKIE_PATH_ENV] = str(home.root / "elsewhere")
            self.assertEqual(paths.cookie_cache_dir(), home.root / "elsewhere")

    def test_legacy_dir_points_at_the_old_temp_location(self):
        self.assertEqual(paths.legacy_cookie_cache_dir().name, "gemini_webapi")


class TestPermissions(unittest.TestCase):
    def test_secure_mkdir_creates_owner_only_directory(self):
        with IsolatedHome() as home:
            created = paths.secure_mkdir(home.gemini_home / "cache" / "deep")
            self.assertTrue(created.is_dir())
            if sys.platform != "win32":
                self.assertEqual(created.stat().st_mode & 0o777, 0o700)

    def test_secure_mkdir_is_idempotent(self):
        with IsolatedHome() as home:
            first = paths.secure_mkdir(home.gemini_home / "cache")
            second = paths.secure_mkdir(home.gemini_home / "cache")
            self.assertEqual(first, second)

    def test_harden_file_restricts_mode(self):
        with IsolatedHome() as home:
            target = home.root / "secret.json"
            target.write_text("{}", encoding="utf-8")
            if sys.platform != "win32":
                target.chmod(0o644)
                self.assertTrue(paths.is_group_or_world_readable(target))
            paths.harden_file(target)
            self.assertFalse(paths.is_group_or_world_readable(target))

    def test_world_readable_check_is_false_for_missing_files(self):
        with IsolatedHome() as home:
            self.assertFalse(paths.is_group_or_world_readable(home.root / "nope.json"))


if __name__ == "__main__":
    unittest.main()
