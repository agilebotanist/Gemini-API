# Changelog

This fork's changes only. Upstream's history is in its own release notes; version
numbers here mean "this fork's build of upstream 2.x" (see `FORK.md`).

## [Unreleased] — 2026-08-24

The auth revamp: a session you can establish once and refresh unattended, and
credential handling that treats Google session cookies as secrets.

### Added

* **`gemini-web login`** — interactive Google sign-in through a real Chromium against a
  persistent profile, capturing the session from the browser's cookie jar rather than a
  DOM selector. `--headless` refreshes the same profile with no interaction, which is
  the unattended recovery path. (ADR-0002)
* **Shared session with `notebooklm`** — by default the session file and browser profile
  are the ones `notebooklm-py` already uses, so one login serves both tools. Writes
  merge and preserve everything we do not own; the shared rung joins an existing
  session and never fabricates one. (ADR-0003)
* **Rotation write-back** — every `__Secure-1PSIDTS` rotation is merged back into the
  session file under a lock byte-compatible with `notebooklm`'s, so the two tools stop
  invalidating each other's credential. (ADR-0006)
* **`gemini-web auth status`** — resolved session file, its source, cookie fingerprints and
  expiries, sharing/write-back state, Playwright availability. `--json` for machines.
* **`gemini-web doctor`** — checks Playwright, the session, its cookies, file permissions,
  the browser profile, write-back and legacy cache files, and prints a fix per failure.
* **`gemini-web logout`** / **`gemini-web auth purge`** — delete local credential material.
  `logout` leaves a shared session file alone unless `--shared` is passed, and states
  that the Google session itself is still valid server-side.
* **`gemini-web` console script** and `--profile` / `--no-shared` global flags. Multiple
  profiles, one per Google account. (ADR-0007)
* **`gemini_webapi.auth`** — a public, documented credential layer: `resolve`, `status`,
  `fingerprint`, `LoginPlan`, `run_login`, `storage_state`, `cookie_policy`, `locking`.
* **Capture gating and live verification** — a capture that would change *which*
  session is stored is refused unless asked for (`--switch-account`) and proven live
  against Gemini first; an unreachable probe refuses too. Found by the first real
  headless run, which overwrote a working credential with a stale cookie from the
  browser profile. New statuses `mismatch` / `unverified`, exit code 3, and
  `gemini_webapi.auth.verify`. (ADR-0009)
* **246 offline tests** (`pytest`, ~6s): hermetic, no network, no browser, no
  credentials. Playwright is behind an injectable seam. (ADR-0008)
* **Docs**: `FORK.md`, `docs/auth.md`, `docs/security.md`, `docs/development.md`,
  `SECURITY.md`, `docs/adr/0001-0008`, and a `SKILL.md` for Claude Code.
* **CI** for the fork: lint, offline tests on 3.11-3.13, and a `gitleaks` secret scan;
  matching pre-commit hooks.

### Changed

* **Cookie cache moved and renamed.** Was
  `%TEMP%/gemini_webapi/.cached_cookies_<the raw __Secure-1PSID>.json` — a bearer
  credential in a filename, in a directory other users can list. Now
  `~/.gemini-webapi/cache/.cached_cookies_<sha256[:32]>.json`, 0600 in a 0700 directory.
  `GEMINI_COOKIE_PATH` still overrides. Old files are found by `doctor`, removed by
  `auth purge`, and cleaned up by `login`. (ADR-0005)
* **The init handshake gained a rung.** `get_access_token` now tries the stored session
  after the cache and explicit cookies, and before another browser's cookie database.
* **Cache-group session keying** reads `__Secure-1PSID` from the jar instead of slicing
  it out of the filename, which is a digest now.
* **The package logger scrubs.** `gemini_webapi`'s bound loguru logger is patched at
  definition time, so registered credential values and cookie-shaped strings are
  replaced with fingerprints in every record it emits. The host application's logging
  is untouched.
* **CLI moved** to `src/gemini_webapi/cli/`; root `cli.py` remains as a shim and still
  exports `main` and `build_parser`. (ADR-0007)
* **`packages.find`** now includes `gemini_webapi*`, so the new subpackages ship in a
  wheel rather than only working in an editable install.
* **Default `pytest` target** is the offline suite; upstream's live tests are run by
  path, deliberately.
* Auth failures in the CLI now tell you to run `gemini-web login --headless` instead of
  "re-export cookies from your browser".
* The console script is **`gemini-web`** (with `gemini-webapi` as an alias), not
  `gemini`: Google's own `gemini-cli` owns that name wherever it is installed, and a
  shadowed entry point is a support ticket waiting to happen.

### Security

* Exactly two cookies (`__Secure-1PSID`, `__Secure-1PSIDTS`) on `.google.com` are read,
  stored or transmitted; everything else is dropped at the boundary. (ADR-0004)
* Cookie values containing CR/LF/NUL/TAB/`;` are rejected — header-injection primitives
  once they reach an HTTP client.
* Profile names must be a single path segment; `../` is rejected, not sanitised.
* Session files are written atomically (`O_EXCL` temp + `os.replace`), 0600, in 0700
  directories; a failed write unlinks its temp file rather than leaving a credential.
* Every human-visible surface prints `sha256:` fingerprints. `Credentials.__repr__`,
  `CookieRowError` and the status reports are all value-free by construction, and
  `tests/unit/test_no_secret_leak.py` proves it from the outside.
* `GEMINI_SECURE_1PSID` still works and is now flagged as a risk by `auth status` and
  `doctor`.
* The credential probe runs with cookie persistence disabled (temp cache directory,
  write-back off), so verifying a session cannot be the thing that stores it.
