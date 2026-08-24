# ADR-0005 — Fingerprints everywhere, values nowhere

* Status: Accepted
* Date: 2026-08-24

## Context

`__Secure-1PSID` is a bearer credential for a Google account. Anyone holding it can use
the Gemini web app as that account until it expires. So the interesting question is not
"is it encrypted at rest" (it cannot be — we have to send it) but **"how many places
does it end up where nobody expected it?"**

The answers found in the pre-fork code and in normal library behaviour:

1. **A filename.** The rotation cache was
   `%TEMP%/gemini_webapi/.cached_cookies_<THE ENTIRE __Secure-1PSID VALUE>.json`. The
   file was `chmod 600`, which is beside the point: the *name* was the secret, in a
   directory every user on the host can list. On Windows `%TEMP%` is per-user, on a
   shared Linux host `/tmp` is not.
2. **Log lines.** `--verbose` printed cookie jars; a dependency's traceback prints
   whatever was in the request.
3. **Dataclass reprs.** Any object holding a cookie prints it in a traceback, a pytest
   assertion diff, or an f-string a caller wrote.
4. **Diagnostics.** The obvious implementation of `auth status` prints the cookie so
   you can compare it with another tool's.

Question 4 is the one that reveals the design: nobody actually needs the *value*. They
need to know whether two things are the same, and whether something changed.

## Decision

**Fingerprints are the currency of every human-visible surface.** `fingerprint(value)`
returns `sha256:` plus 8 hex characters of the digest — enough to compare, useless to
replay. `-` means absent, which is a normal state for `__Secure-1PSIDTS` and must not
look like a value. Every status field, log line, CLI table and `__repr__` in the auth
layer prints a fingerprint.

**Scrubbing is the backstop.** `register_secret()` puts values into a process-wide
registry at the moment they enter (session-file read, browser capture, env parse), and
the package's loguru logger is patched at definition time so every record it emits
passes through `scrub()`. Scrubbing also catches values this process never registered,
by shape: `NAME=value` for known-sensitive cookie names, `"NAME": "value"` JSON pairs,
and bare `g.a0…` Google tokens. Belt and braces — the primary control is that our own
code passes fingerprints.

**Names never carry values.** The cache filename is
`.cached_cookies_<sha256(psid)[:32]>.json`, and the cache moved out of the shared temp
directory into `~/.gemini-webapi/cache/`. `gemini-web auth purge` deletes files an older
install left in the old location; `gemini-web doctor` reports them; `gemini-web login` cleans
them up on the way past.

**Permissions and atomicity.** Directories 0700, files 0600 (POSIX; on Windows the
inherited ACL governs and `doctor` reports rather than asserts). Writes go to a
sibling temp file opened `O_EXCL | 0600` and are `os.replace`d into place, and a failed
write unlinks the temp file rather than leaving a credential in it.

**Environment variables are supported but flagged.** `GEMINI_SECURE_1PSID` works, and
both `auth status` and `doctor` warn when it is set: environment variables are
inherited by child processes and captured by crash reporters.

## Consequences

* No surface in the auth layer prints a credential, and `tests/unit/test_no_secret_leak.py`
  proves it from the outside: a known cookie goes into a session file, every CLI
  command and object repr is rendered, and the output is searched for the value, its
  16-character prefix and its URL-quoted form.
* Diagnostics stay useful. "Is `gemini-web` on the same session as `notebooklm`?" is
  answered by comparing two fingerprints.
* Comparing a fingerprint to a *value* requires hashing the value first — mildly
  inconvenient, deliberately.
* The scrubber costs a string pass per log record. Irrelevant at this package's log
  volume.
* 8 hex characters is a collision every ~4 billion values. For "did this change?" that
  is fine; nobody should build an identity system on it.

## Alternatives considered

**Print the last 4 characters of the cookie.** Cheaper to eyeball, and it leaks key
material — the pattern credit cards use because the rest of the number is protected
elsewhere. Not applicable to a bearer token.

**OS keyring for storage.** Genuinely better at rest, and it breaks the whole point of
ADR-0003: a keyring entry is not a file another tool can read, and it does not work
headless on Linux without a session bus. The shared, owner-only file is the trade.

**Encrypt the session file with a passphrase.** Moves the secret to wherever the
passphrase lives; for an unattended agent that is the same disk.
