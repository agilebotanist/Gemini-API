# ADR-0002 — Make a real browser login the primary auth path

* Status: Accepted
* Date: 2026-08-24

## Context

Gemini's web endpoints authenticate with Google session cookies —
`__Secure-1PSID` and the rotating `__Secure-1PSIDTS`. Upstream offers two ways to get
them:

**Read another browser's cookie database** (`browser-cookie3`). Convenient when it
works, and it frequently does not:

* Chrome's app-bound encryption on Windows makes the cookie file unreadable by other
  processes; on this machine `browser-cookie3` finds nothing at all (verified: every
  browser backend fails, which is why the handshake falls through to the guest rung).
* Firefox needs the profile unlocked; Safari needs Full Disk Access.
* It reads *all* cookies for the domain, and upstream had to filter down to two names
  because sending the rest makes `RotateCookies` answer 401.

**Paste the cookie by hand** out of devtools, into a JSON file or an environment
variable. Works exactly once. `__Secure-1PSIDTS` rotates on the order of minutes, and
`__Secure-1PSID` expires eventually, so this is a recurring manual chore in a tool whose
whole purpose is automation.

Neither can recover unattended. For an agent that runs Deep Research overnight, "the
session expired, ask a human to re-paste a cookie" is the failure that matters.

There is a third way, and NotebookLM's client already proved it in this environment:
drive a real browser with Playwright against a **persistent profile**, let the human
sign in once, and read the cookies out of the browser context.

## Decision

`gemini-web login` launches a persistent Chromium context, navigates to
`https://gemini.google.com/app`, and polls the context's cookie jar until
`__Secure-1PSID` appears. The captured cookies are merged into a Playwright
`storage_state.json`; the browser profile directory is kept.

Because the profile persists, `gemini-web login --headless` can re-run the same flow with no
window and no interaction: Google re-issues the rotating cookie to a profile that still
holds a valid session. That is the command an automated recovery path calls.

Playwright is an **optional** extra (`pip install "gemini-webapi[playwright]"`). The
library still works from an existing session file, an environment variable, or the
browser-cookie fallback, on hosts where no browser can run.

Detection is by **cookie jar, not by DOM**. Google's sign-in crosses several origins,
A/B-tests its markup, and inserts consent and device prompts. A selector-based wait is
a bet on a layout; the presence of a session cookie is the actual definition of
"signed in", and it is what the caller needs anyway.

## Consequences

* First login is interactive, once, and then unattended refresh works for as long as
  Google keeps the profile's session alive (weeks, in practice) — *provided the profile
  is where the live session actually lives. A profile whose session was minted by
  another route can hold a stale cookie, which is why a capture no longer replaces a
  stored session without proving itself (ADR-0009).*
* A ~100 MB browser and a Chromium download join the dependency tree — for the people
  who want the feature only, hence the extra.
* The Windows event-loop hazard is real: Playwright needs a loop that can spawn
  subprocesses, so the login runner names `ProactorEventLoop` explicitly rather than
  relying on (or mutating) the host's event-loop policy.
* Two processes cannot drive one profile directory; Chromium locks it. That surfaces as
  a clear launch error, which is the correct outcome (ADR-0003).
* The login flow is testable without a browser, because the Playwright surface is one
  injectable `launcher` seam (ADR-0008).

## Alternatives considered

**Google's official API with an API key.** The right answer for anything that must not
break — and a different product: no Deep Research, no Gems, no web-app quota. Named in
the skill docs as the alternative for infrastructure.

**OAuth device flow.** There is no Google OAuth scope that grants the Gemini web app's
internal endpoints. The web session is the only credential these endpoints accept.

**A browser extension that exports cookies on a schedule.** More moving parts, another
thing to install and trust, and it still cannot re-authenticate when the session dies.
