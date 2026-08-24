"""The stored session as a rung of ``get_access_token``'s cookie ladder.

``get_access_token`` itself needs the network, so what is tested here is the offline
decision it delegates: does the storage state contribute a candidate jar, and is that
jar skipped in the cases where using it would be wrong?
"""

from __future__ import annotations

import unittest

from gemini_webapi.utils.get_access_token import _storage_state_jars

from ._support import FAKE_PSID, FAKE_PSIDTS, OTHER_PSID, IsolatedHome


class TestStorageStateJars(unittest.TestCase):
    def test_offers_a_jar_from_the_stored_session(self):
        with IsolatedHome() as home:
            home.write_storage(home.shared_storage())
            jars = _storage_state_jars(None, {})
            self.assertEqual(len(jars), 1)
            jar, name, psid = jars[0]
            self.assertEqual(name, "Stored Session")
            self.assertEqual(psid, FAKE_PSID)
            values = {cookie.name: cookie.value for cookie in jar.jar}
            self.assertEqual(values["__Secure-1PSID"], FAKE_PSID)
            self.assertEqual(values["__Secure-1PSIDTS"], FAKE_PSIDTS)

    def test_nothing_when_there_is_no_session(self):
        with IsolatedHome():
            self.assertEqual(_storage_state_jars(None, {}), [])

    def test_skipped_when_the_caller_supplied_a_different_account(self):
        # Silently authenticating as the other account in the file would be worse than
        # failing: the caller asked for a specific session.
        with IsolatedHome() as home:
            home.write_storage(home.own_storage(), psid=OTHER_PSID)
            self.assertEqual(_storage_state_jars(FAKE_PSID, {}), [])

    def test_used_when_the_caller_supplied_the_same_account(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            self.assertEqual(len(_storage_state_jars(FAKE_PSID, {})), 1)

    def test_skipped_when_the_cache_already_covered_the_pair(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            tried = {FAKE_PSID: {FAKE_PSIDTS}}
            self.assertEqual(_storage_state_jars(None, tried), [])

    def test_offered_when_the_cache_has_a_stale_psidts(self):
        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            tried = {FAKE_PSID: {"sidts-CjIBstaleCachedValue"}}
            self.assertEqual(len(_storage_state_jars(None, tried)), 1)

    def test_corrupt_session_file_is_skipped_quietly(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("<not json>", encoding="utf-8")
            self.assertEqual(_storage_state_jars(None, {}), [])

    def test_verbose_logging_stays_value_free(self):
        import io

        from loguru import logger as root_logger

        with IsolatedHome() as home:
            home.write_storage(home.own_storage())
            sink = io.StringIO()
            handler = root_logger.add(sink, level="DEBUG", format="{message}")
            try:
                _storage_state_jars(None, {}, verbose=True)
                _storage_state_jars(OTHER_PSID, {}, verbose=True)
            finally:
                root_logger.remove(handler)
            captured = sink.getvalue()
            self.assertIn("sha256:", captured)
            self.assertNotIn(FAKE_PSID, captured)


class TestCacheGroupNaming(unittest.TestCase):
    def test_latest_cache_group_keys_on_the_jar_not_the_filename(self):
        # The filename is a digest now; slicing it as a session id would key the
        # de-duplication map on a hash and silently disable it.
        import inspect
        import sys

        # `from gemini_webapi.utils import get_access_token` yields the re-exported
        # *function*, so reach for the module through sys.modules.
        module = sys.modules["gemini_webapi.utils.get_access_token"]

        source = inspect.getsource(module.get_access_token)
        self.assertIn('_extract_cookie_value(jar, "__Secure-1PSID")', source)
        self.assertNotIn("cache_file.stem[16:]", source)


if __name__ == "__main__":
    unittest.main()
