"""Live-credential verification, with the network stubbed out.

The probe's own request is upstream's init handshake and is not re-tested here. What is
tested is everything around it, because that is where the damage would be: the
three-valued verdict, and the guarantee that a probe cannot persist the credential it
was asked to judge.
"""

from __future__ import annotations

import asyncio
import os
import unittest

from gemini_webapi.auth import paths as auth_paths
from gemini_webapi.auth import verify

from ._support import FAKE_PSID, FAKE_PSIDTS, IsolatedHome


class TestVerifyResult(unittest.TestCase):
    def test_three_valued_verdict(self):
        self.assertTrue(verify.VerifyResult(True, "AVAILABLE", "").authenticated)
        self.assertFalse(verify.VerifyResult(False, "UNAUTHENTICATED", "").authenticated)
        self.assertFalse(verify.VerifyResult(None, "unknown", "").authenticated)
        self.assertTrue(verify.VerifyResult(None, "unknown", "").unknown)
        self.assertFalse(verify.VerifyResult(False, "UNAUTHENTICATED", "").unknown)

    def test_repr_carries_no_value(self):
        result = verify.VerifyResult(True, "AVAILABLE", "fine", psid="sha256:abcd1234")
        self.assertNotIn(FAKE_PSID, repr(result))


class TestProbeOutcomes(unittest.TestCase):
    """`averify_credentials` translates the probe's answer into a verdict."""

    def _run(self, probe):
        original = verify._probe
        verify._probe = probe
        try:
            return asyncio.run(verify.averify_credentials(FAKE_PSID, FAKE_PSIDTS))
        finally:
            verify._probe = original

    def test_authenticated_session(self):
        async def probe(*_args, **_kwargs):
            return "AVAILABLE", "Account is available.", True

        result = self._run(probe)
        self.assertIs(result.ok, True)
        self.assertEqual(result.status, "AVAILABLE")
        self.assertTrue(result.psid.startswith("sha256:"))

    def test_guest_session_is_a_rejection(self):
        # The live failure that motivated this module: structurally perfect cookies,
        # unauthenticated session (ADR-0009).
        async def probe(*_args, **_kwargs):
            return "UNAUTHENTICATED", "Session is not authenticated.", False

        result = self._run(probe)
        self.assertIs(result.ok, False)
        self.assertEqual(result.status, "UNAUTHENTICATED")

    def test_network_failure_is_unknown_not_invalid(self):
        async def probe(*_args, **_kwargs):
            raise ConnectionError("no route to host")

        result = self._run(probe)
        self.assertIsNone(result.ok)
        self.assertEqual(result.status, "unknown")
        self.assertIn("Could not reach Gemini", result.detail)

    def test_failure_detail_names_the_error_type_not_the_credential(self):
        async def probe(*_args, **_kwargs):
            raise RuntimeError(f"401 for {FAKE_PSID}")

        result = self._run(probe)
        self.assertIn("RuntimeError", result.detail)
        self.assertNotIn(FAKE_PSID, result.detail)

    def test_sync_wrapper_runs_the_coroutine(self):
        async def probe(*_args, **_kwargs):
            return "AVAILABLE", "ok", True

        original = verify._probe
        verify._probe = probe
        try:
            self.assertIs(verify.verify_credentials(FAKE_PSID, FAKE_PSIDTS).ok, True)
        finally:
            verify._probe = original


class TestPersistenceSuppression(unittest.TestCase):
    """A probe must not be able to save the credential it is judging."""

    def test_cache_is_redirected_and_writeback_disabled_inside(self):
        with IsolatedHome() as home:
            observed = {}

            async def probe(*_args, **_kwargs):
                observed["cache"] = os.environ[auth_paths.GEMINI_COOKIE_PATH_ENV]
                observed["writeback"] = os.environ[auth_paths.GEMINI_AUTH_WRITEBACK_ENV]
                observed["enabled"] = auth_paths.writeback_enabled()
                return "AVAILABLE", "ok", True

            original = verify._probe
            verify._probe = probe
            try:
                asyncio.run(verify.averify_credentials(FAKE_PSID, FAKE_PSIDTS))
            finally:
                verify._probe = original

            self.assertNotEqual(observed["cache"], str(home.gemini_home / "cache"))
            self.assertEqual(observed["writeback"], "0")
            self.assertFalse(observed["enabled"])

    def test_environment_is_restored_afterwards(self):
        with IsolatedHome():
            os.environ[auth_paths.GEMINI_COOKIE_PATH_ENV] = "sentinel-value"

            async def probe(*_args, **_kwargs):
                return "AVAILABLE", "ok", True

            original = verify._probe
            verify._probe = probe
            try:
                asyncio.run(verify.averify_credentials(FAKE_PSID, FAKE_PSIDTS))
            finally:
                verify._probe = original

            self.assertEqual(os.environ[auth_paths.GEMINI_COOKIE_PATH_ENV], "sentinel-value")
            self.assertNotIn(auth_paths.GEMINI_AUTH_WRITEBACK_ENV, os.environ)

    def test_environment_is_restored_even_when_the_probe_raises(self):
        with IsolatedHome():

            async def probe(*_args, **_kwargs):
                raise ConnectionError("boom")

            original = verify._probe
            verify._probe = probe
            try:
                asyncio.run(verify.averify_credentials(FAKE_PSID, FAKE_PSIDTS))
            finally:
                verify._probe = original

            self.assertNotIn(auth_paths.GEMINI_COOKIE_PATH_ENV, os.environ)
            self.assertNotIn(auth_paths.GEMINI_AUTH_WRITEBACK_ENV, os.environ)

    def test_temp_cache_directory_is_cleaned_up(self):
        with IsolatedHome():
            captured = {}

            async def probe(*_args, **_kwargs):
                captured["dir"] = os.environ[auth_paths.GEMINI_COOKIE_PATH_ENV]
                return "AVAILABLE", "ok", True

            original = verify._probe
            verify._probe = probe
            try:
                asyncio.run(verify.averify_credentials(FAKE_PSID, FAKE_PSIDTS))
            finally:
                verify._probe = original

            self.assertFalse(os.path.exists(captured["dir"]))


if __name__ == "__main__":
    unittest.main()
