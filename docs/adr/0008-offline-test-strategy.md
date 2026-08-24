# ADR-0008 — Test the decisions, not the browser

* Status: Accepted
* Date: 2026-08-24

## Context

Upstream's test suite is a set of live integration tests: `setUp` builds a real client
and calls `gemini.google.com`. They are valuable — they are how you learn Google changed
an endpoint — and they are unusable as a development loop or in CI: they need a Google
account, they are slow, they are rate-limited, and a failure means "something, somewhere,
changed".

The auth layer's risk profile is the opposite. Its bugs are decisions, not requests:
writing the wrong file, clobbering another tool's document, printing a cookie, skipping
a write-back that should have happened, keying a de-duplication map on a hash.

## Decision

A second suite, `tests/unit/`, that is **hermetic**: no network, no browser, no
credentials, no writes outside a temporary directory. It is the default `pytest` target
(`testpaths = ["tests/unit"]`); upstream's live tests are run deliberately, by path.

Four devices carry it:

**`IsolatedHome`.** Every path in the auth layer is redirectable by environment
variable, and this fixture redirects *all* of them at once — including the ones a given
test does not think it uses, because a missed variable means silently exercising the
developer's real `~/.notebooklm`. It also restores "was unset", which matters on a
machine where `GEMINI_SECURE_1PSID` is genuinely exported.

**An injectable browser.** `capture()` takes a `launcher` callable; the default builds a
real Chromium context, the tests pass a `FakeContext` whose `cookie_schedule` expresses
"signed out for two polls, then signed in" with no timing at all. Same seam for the
poll loop's clock and sleep, so the timeout path is tested in microseconds.

**Realistic secrets.** The fixtures' cookie values carry the `g.a0` prefix and the
length of real ones, because the scrubber's heuristics key on exactly that. A test
using `"secret123"` would pass while the shipped code leaked.

**An outside-in leak test.** `test_no_secret_leak.py` does not check components; it puts
a known cookie in a session file, renders every CLI command and object repr, and greps
for the value, its 16-character prefix and its URL-quoted form. It is the test that
fails when someone adds a helpful debug line in six months.

Framework is stdlib `unittest`, matching upstream, and it runs under `pytest` too.

## Consequences

* 229 tests, ~4 seconds, no credentials — a real edit-run loop, and something CI can run
  on every push.
* Playwright's own behaviour is *not* tested. If Playwright changes how a persistent
  context reports cookies, only a live login catches it. Accepted: that is one thin
  adapter (`_default_launcher`), and the alternative is a browser download in CI to test
  code we did not write.
* Two suites means two commands, documented in `docs/development.md` and enforced by the
  `pytest` default.
* A few tests reach into private helpers (`resolver._legacy_cache_files`,
  `locking._os_lock`, `_storage_state_jars`). Deliberate: those *are* the decisions, and
  a white-box assertion on a documented seam beats no coverage of a security-relevant
  branch.

## Alternatives considered

**Mock at the HTTP layer and test through `GeminiClient.init()`.** Broader coverage,
and it would pin us to upstream's request internals — the code most likely to change
under a merge. The auth ladder's contribution is one function (`_storage_state_jars`),
tested directly.

**A Playwright-in-CI job.** Real coverage of the browser adapter, ~100 MB download and
minutes per run, for a file that does one thing. Reconsider if `_default_launcher` ever
grows logic.
