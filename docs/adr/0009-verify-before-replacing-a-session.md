# ADR-0009 — A capture must earn the right to replace a stored session

* Status: Accepted
* Date: 2026-08-24
* Supersedes part of: [ADR-0002](0002-playwright-login.md) (which persisted every capture)

## Context

This one is not a design hypothesis. It is what the first live run of
`gemini-web login --headless` did.

The machine had a working session: `notebooklm` had established it, and
`gemini-web models` authenticated with it happily. The headless refresh launched the
shared browser profile, read its cookie jar, found `__Secure-1PSID` on `.google.com` —
structurally perfect, far-future expiry — and wrote it into the shared session file,
replacing the stored one. Fingerprints before and after:

```
stored:   sha256:ee32ab7d   expires 2028-08-23   ← authenticates
captured: sha256:6fc25ec7   expires 2027-06-17   ← guest session
```

Probing the captured pair directly:

```
Using credentials from storage ($GEMINI_AUTH_STORAGE) (psid=sha256:6fc25ec7)
Init attempt (1) from Base Cookies succeeded.
Account status: UNAUTHENTICATED - Session is not authenticated or cookies have expired.
```

The browser profile's `.google.com` cookie was **stale**. The working session had been
minted another way (NotebookLM's master-token path), so "the browser profile is
authoritative" — the assumption behind persisting whatever the capture found — is simply
false. A single unattended refresh destroyed a working credential and required an
interactive login to recover.

Two distinct assumptions failed:

1. *A cookie that looks right is a cookie that works.* It is a bearer token; the only
   test is to use it.
2. *A capture from "the" profile is the same session as the stored one.* A browser
   profile can hold several accounts, stale cookies from a previous sign-in, and
   per-ccTLD copies (`.google.fr` here, alongside `.google.com`).

## Decision

A capture that would **change which session is stored** has to pass two gates. A
capture that only refreshes the *rotating* token of the *same* session passes freely —
that is the common case, and the point of the feature.

**Gate 1 — the switch must be asked for.** If the file already holds a
`__Secure-1PSID` and the capture's differs, nothing is written. Status `mismatch`, exit
code 3, and a message that says the stored session is probably still the good one.
`gemini-web login --switch-account` is how a person says "yes, that other account is
what I want".

**Gate 2 — the new session must prove it works.** With the switch allowed, the captured
pair is probed against Gemini through the package's own init handshake, and persisted
only if the account status is not `UNAUTHENTICATED`. Status `unverified` otherwise, and
again nothing is written. `--no-verify` waives it, for someone who knows better than
the probe.

Three supporting rules:

* **Unknown is not a verdict.** A probe that cannot reach Gemini returns `None`, and
  `None` refuses the overwrite. A network hiccup must not cost a working credential.
* **The probe cannot persist what it is judging.** `GeminiClient.close()` writes cookies
  to the cache and back to the session file, so the verifier runs with the cache
  redirected to a temp directory and `GEMINI_AUTH_WRITEBACK=0`. Otherwise the check
  would leak the very credential it was gating.
* **The verifier is an injected seam.** `capture(..., verifier=...)`, so the whole flow
  stays testable offline; `tests/unit/test_playwright_login.py` covers refuse-by-
  default, allowed-and-verified, unauthenticated, unreachable and waived.

## Consequences

* An unattended refresh can no longer destroy a session. Worst case it reports
  `mismatch`/`unverified` and leaves everything alone — recoverable, and legible.
* A genuine account switch costs one extra flag and one extra HTTP round trip. Correct
  trade for an operation that overwrites a credential shared with another tool.
* `mismatch` is now the *expected* result of `--headless` on this machine, because the
  browser profile's cookie is not the working one. That is information, not a bug: the
  right recovery here is an interactive `gemini-web login`, and the message says so.
* Exit code 3 (`EXIT_NOT_REPLACED`) joins the CLI's contract, so a wrapper can tell
  "nothing was written, your session is probably fine" from "login failed".
* The headless-refresh story is weaker than ADR-0002 claimed: it works when the browser
  profile *is* where the live session lives, which is true for a profile our own
  interactive login created, and false for one whose session was minted elsewhere. The
  docs say this plainly rather than promising unattended recovery everywhere.

## Alternatives considered

**Trust the capture, and let the next request fail.** What the code did, and what this
ADR exists to undo. The failure lands far from the cause, and by then the good
credential is gone.

**Verify every capture, including same-session refreshes.** One HTTP request per
refresh for a case that carries no risk — the session id is unchanged, so there is
nothing to lose. Skipped on purpose.

**Keep a backup of the previous session and roll back on the next auth failure.** More
machinery, and a rollback window in which two tools disagree about the current
credential. Refusing the write is simpler and has no window.

**Prefer the row whose PSID matches the stored one, silently.** Tempting — it fixes the
observed case without a flag. Rejected: it also silently hides a real account switch,
and it cannot help when the stored session is the one that has actually expired.
