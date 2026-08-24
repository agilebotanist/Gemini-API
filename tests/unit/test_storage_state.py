"""Reading and writing the session file, including "do not clobber notebooklm"."""

from __future__ import annotations

import json
import sys
import unittest

from gemini_webapi.auth import storage_state as store

from ._support import (
    FAKE_PSID,
    FAKE_PSIDTS,
    FUTURE,
    OTHER_PSID,
    PAST,
    IsolatedHome,
    cookie_row,
)

NOTEBOOKLM_KEY = {"notebooklm": {"account": {"email_hash": "abc123", "index": 0}}}


class TestLoad(unittest.TestCase):
    def test_missing_file_is_not_an_error(self):
        with IsolatedHome() as home:
            state = store.load(home.own_storage())
            self.assertFalse(state.exists)
            self.assertEqual(state.cookies, [])
            self.assertIsNone(state.psid)

    def test_loads_credentials(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            state = store.load(path)
            self.assertTrue(state.exists)
            self.assertEqual(state.psid, FAKE_PSID)
            self.assertEqual(state.psidts, FAKE_PSIDTS)

    def test_empty_file_reads_as_no_credentials(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("   ", encoding="utf-8")
            state = store.load(path)
            self.assertTrue(state.exists)
            self.assertIsNone(state.psid)

    def test_corrupt_json_raises_in_strict_mode(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(store.StorageStateError):
                store.load(path)
            # ...and degrades quietly when the caller has other sources to try.
            self.assertIsNone(store.load(path, strict=False).psid)

    def test_json_array_is_rejected(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            path.parent.mkdir(parents=True)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(store.StorageStateError):
                store.load(path)

    def test_unrelated_cookies_are_dropped_from_the_projection(self):
        with IsolatedHome() as home:
            path = home.write_storage(
                home.own_storage(),
                extra_cookies=[cookie_row("SAPISID", "some-other-sensitive-value")],
            )
            state = store.load(path)
            self.assertEqual(len(state.cookies), 2)
            # ...but the document keeps them, so a save cannot delete them.
            self.assertEqual(len(state.document["cookies"]), 3)

    def test_expired_cookies_are_not_offered_as_credentials(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage(), expires=PAST)
            self.assertIsNone(store.load(path).psid)


class TestSummary(unittest.TestCase):
    def test_summary_is_value_free(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage(), foreign=NOTEBOOKLM_KEY)
            summary = store.load(path).summary()
            serialised = json.dumps(summary)
            self.assertNotIn(FAKE_PSID, serialised)
            self.assertNotIn(FAKE_PSIDTS, serialised)
            self.assertTrue(summary["psid"].startswith("sha256:"))

    def test_summary_reports_foreign_keys_and_counts(self):
        with IsolatedHome() as home:
            path = home.write_storage(
                home.own_storage(),
                foreign=NOTEBOOKLM_KEY,
                extra_cookies=[cookie_row("SID", "x" * 40)],
            )
            summary = store.load(path).summary()
            self.assertEqual(summary["foreign_keys"], ["notebooklm"])
            self.assertEqual(summary["usable_cookies"], 2)
            self.assertEqual(summary["total_cookies"], 3)
            self.assertTrue(summary["psid_expires"].endswith("Z"))


class TestMerge(unittest.TestCase):
    def test_replaces_in_place_and_reports_the_change(self):
        document = {"cookies": [cookie_row("__Secure-1PSIDTS", "sidts-CjIBoldRotatedValue00")]}
        merged, changed = store.merge_cookies(
            document, [cookie_row("__Secure-1PSIDTS", FAKE_PSIDTS)]
        )
        self.assertEqual(changed, ["__Secure-1PSIDTS"])
        self.assertEqual(len(merged["cookies"]), 1)
        self.assertEqual(merged["cookies"][0]["value"], FAKE_PSIDTS)

    def test_appends_a_new_cookie(self):
        document = {"cookies": [cookie_row("SAPISID", "other")]}
        merged, changed = store.merge_cookies(document, [cookie_row("__Secure-1PSID", FAKE_PSID)])
        self.assertEqual(changed, ["__Secure-1PSID"])
        self.assertEqual(len(merged["cookies"]), 2)

    def test_identical_value_is_not_a_change(self):
        document = {"cookies": [cookie_row("__Secure-1PSID", FAKE_PSID)]}
        _, changed = store.merge_cookies(document, [cookie_row("__Secure-1PSID", FAKE_PSID)])
        self.assertEqual(changed, [])

    def test_metadata_refreshes_even_without_a_value_change(self):
        document = {"cookies": [cookie_row("__Secure-1PSID", FAKE_PSID, expires=FUTURE - 1000)]}
        merged, _ = store.merge_cookies(
            document, [cookie_row("__Secure-1PSID", FAKE_PSID, expires=FUTURE)]
        )
        self.assertEqual(merged["cookies"][0]["expires"], FUTURE)

    def test_foreign_cookies_and_keys_survive(self):
        document = {
            "cookies": [cookie_row("SAPISID", "keep-me"), cookie_row("SID", "keep-me-too")],
            **NOTEBOOKLM_KEY,
        }
        merged, _ = store.merge_cookies(document, [cookie_row("__Secure-1PSID", FAKE_PSID)])
        names = [row["name"] for row in merged["cookies"]]
        self.assertIn("SAPISID", names)
        self.assertIn("SID", names)
        self.assertEqual(merged["notebooklm"], NOTEBOOKLM_KEY["notebooklm"])

    def test_malformed_existing_rows_are_left_alone(self):
        document = {"cookies": ["garbage", {"no": "name"}]}
        merged, changed = store.merge_cookies(document, [cookie_row("__Secure-1PSID", FAKE_PSID)])
        self.assertEqual(changed, ["__Secure-1PSID"])
        self.assertEqual(len(merged["cookies"]), 3)


class TestSave(unittest.TestCase):
    def test_writes_owner_only_and_atomically(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            store.save(path, {"cookies": [cookie_row("__Secure-1PSID", FAKE_PSID)]})
            self.assertTrue(path.exists())
            if sys.platform != "win32":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            # No temp file left behind.
            self.assertEqual([p.name for p in path.parent.glob("*.tmp")], [])

    def test_round_trips(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            document = {"cookies": [cookie_row("__Secure-1PSID", FAKE_PSID)], "custom": {"a": 1}}
            store.save(path, document)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["custom"], {"a": 1})

    def test_failed_serialisation_leaves_no_temp_file_and_no_damage(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            before = path.read_text(encoding="utf-8")
            with self.assertRaises(TypeError):
                store.save(path, {"cookies": [], "bad": object()})
            self.assertEqual(path.read_text(encoding="utf-8"), before)
            self.assertEqual([p.name for p in path.parent.glob("*.tmp")], [])


class TestUpdateCredentials(unittest.TestCase):
    def test_writes_the_rotated_token(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            changed = store.update_credentials(path, psid=FAKE_PSID, psidts="sidts-CjIBnewRotated1")
            self.assertEqual(changed, ["__Secure-1PSIDTS"])
            self.assertEqual(store.load(path).psidts, "sidts-CjIBnewRotated1")

    def test_no_write_when_already_current(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            mtime = path.stat().st_mtime_ns
            self.assertEqual(store.update_credentials(path, psid=FAKE_PSID, psidts=FAKE_PSIDTS), [])
            self.assertEqual(path.stat().st_mtime_ns, mtime)

    def test_refuses_to_write_into_another_accounts_session(self):
        # The shared-file hazard: writing our token next to someone else's PSID
        # produces a mismatched pair and logs the other tool out.
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage(), psid=OTHER_PSID)
            self.assertEqual(
                store.update_credentials(path, psid=FAKE_PSID, psidts=FAKE_PSIDTS),
                [],
            )
            self.assertEqual(store.load(path).psid, OTHER_PSID)

    def test_override_allows_an_account_switch(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage(), psid=OTHER_PSID)
            changed = store.update_credentials(
                path, psid=FAKE_PSID, psidts=FAKE_PSIDTS, require_matching_psid=False
            )
            self.assertIn("__Secure-1PSID", changed)
            self.assertEqual(store.load(path).psid, FAKE_PSID)

    def test_creates_the_file_when_absent(self):
        with IsolatedHome() as home:
            path = home.own_storage()
            self.assertTrue(store.update_credentials(path, psid=FAKE_PSID, psidts=FAKE_PSIDTS))
            self.assertTrue(path.exists())

    def test_nothing_to_do_without_values(self):
        with IsolatedHome() as home:
            self.assertEqual(store.update_credentials(home.own_storage()), [])

    def test_preserves_notebooklms_key_and_cookies(self):
        with IsolatedHome() as home:
            path = home.write_storage(
                home.shared_storage(),
                foreign=NOTEBOOKLM_KEY,
                extra_cookies=[cookie_row("SAPISID", "notebooklm-needs-this")],
            )
            store.update_credentials(path, psid=FAKE_PSID, psidts="sidts-CjIBrotatedByGemini")
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["notebooklm"], NOTEBOOKLM_KEY["notebooklm"])
            self.assertIn("SAPISID", [row["name"] for row in document["cookies"]])
            self.assertEqual(len(document["cookies"]), 3)

    def test_expiry_is_recorded(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage())
            store.update_credentials(
                path, psid=FAKE_PSID, psidts="sidts-CjIBwithExpiry01", expires=FUTURE
            )
            rows = {row["name"]: row for row in store.load(path).cookies}
            self.assertEqual(rows["__Secure-1PSIDTS"]["expires"], FUTURE)


class TestClearCredentials(unittest.TestCase):
    def test_removes_only_our_cookies(self):
        with IsolatedHome() as home:
            path = home.write_storage(
                home.shared_storage(),
                foreign=NOTEBOOKLM_KEY,
                extra_cookies=[cookie_row("SAPISID", "still-here")],
            )
            removed = store.clear_credentials(path)
            self.assertEqual(sorted(removed), ["__Secure-1PSID", "__Secure-1PSIDTS"])
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual([row["name"] for row in document["cookies"]], ["SAPISID"])
            self.assertIn("notebooklm", document)

    def test_missing_file_is_a_no_op(self):
        with IsolatedHome() as home:
            self.assertEqual(store.clear_credentials(home.own_storage()), [])

    def test_nothing_to_remove_leaves_the_file_alone(self):
        with IsolatedHome() as home:
            path = home.write_storage(home.own_storage(), psid=None, psidts=None)
            mtime = path.stat().st_mtime_ns
            self.assertEqual(store.clear_credentials(path), [])
            self.assertEqual(path.stat().st_mtime_ns, mtime)


if __name__ == "__main__":
    unittest.main()
