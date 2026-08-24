# ADR-0004 — Handle exactly two cookies

* Status: Accepted
* Date: 2026-08-24

## Context

A Google sign-in leaves around 40 cookies in a browser profile: `SID`, `HSID`, `SSID`,
`APISID`, `SAPISID`, the `1P`/`3P` families, `LSID`, `__Host-GAPS`, per-service `OSID`s,
analytics. Together they are the keys to the account — Gmail, Drive, account recovery.

Gemini's endpoints need two: `__Secure-1PSID` and (when the account has one)
`__Secure-1PSIDTS`.

Upstream already discovered the functional half of this the hard way: its
browser-cookie path copies a comment saying *"Load only `__Secure-1PSID` and
`__Secure-1PSIDTS` to prevent HTTP 401 errors when rotating cookies."* Sending the full
jar to `RotateCookies` fails.

The security half is ours to state. Every cookie this process reads is a cookie it can
log, cache, write to disk and leak.

## Decision

The auth layer's allowlist is exactly:

```python
ALLOWED_COOKIE_NAMES = {"__Secure-1PSID", "__Secure-1PSIDTS"}
ALLOWED_COOKIE_DOMAINS = {".google.com", "google.com"}
```

Enforced at the boundary in `auth/cookie_policy.py`, so it applies identically to the
three places cookies enter: a browser capture, a session file read, and a cookie jar
handed back by the HTTP client. Domain matching is exact after normalising the leading
dot — no suffix rule, because `accounts.google.com`'s cookies are not what Gemini's
endpoints want and `evil-google.com`'s are not what anyone wants.

Rows are also *sanitised*, not just filtered: a value containing CR, LF, NUL, TAB or
`;` is rejected (header-injection primitive once it reaches an HTTP client), and a
malformed row is skipped with a value-free warning rather than raising — one bad row in
a 40-cookie capture must not fail a login.

One deliberate exception, inherited from upstream: the **rotation cache**
(`~/.gemini-webapi/cache/`) stores the session's working set as the HTTP client saw it,
including consent/anonymous cookies with expiries, because that is what makes the next
cold start succeed offline. It is owner-only, in an owner-only directory, with a hashed
filename (ADR-0005). The *storage state* — the thing shared with another tool and the
thing a user is most likely to copy around — carries two cookies and nothing else.

## Consequences

* A disclosure of what we persist is a Gemini session, not the whole Google account.
* NotebookLM's cookies in a shared file are untouched: not read into our jar, not
  logged, not rewritten (they *are* preserved, per ADR-0003 — preserved is not the same
  as handled).
* Rotation keeps working, which the full jar demonstrably breaks.
* If Google ever requires a third cookie, this is a one-line change in one file — and
  a deliberate one, with a test to update.

## Alternatives considered

**Pass through whatever the browser has.** Maximum compatibility with future endpoint
changes, maximum exposure, and known-broken rotation.

**Store the full Playwright storage state (all 40 cookies) as our session file.** It is
what `browser_context.storage_state()` hands you, so it is the path of least
resistance. Rejected: it turns our session file into a full account credential, and it
would make `gemini-web login` capable of creating a NotebookLM-shaped file that we do not
understand well enough to own.
