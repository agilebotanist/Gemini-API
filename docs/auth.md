# Authentication

Gemini's web endpoints authenticate with Google session cookies. This fork's job is to
get them once, keep them fresh, and never print them.

```bash
pip install -e ".[playwright,browser]"
python -m playwright install chromium

gemini-web login          # a browser opens; sign in once
gemini-web auth status    # confirm what got stored, and where
gemini-web ask "hello"
```

## The five-minute version

| Situation | Command |
|---|---|
| First time, or the session died | `gemini-web login` |
| Session expired, no human around | `gemini-web login --headless` |
| "Which account am I using?" | `gemini-web auth status` |
| "Why doesn't it work?" | `gemini-web doctor` |
| Delete local credentials | `gemini-web logout` |

## Where the session lives

By default, in NotebookLM's profile — because a Google session is a Google session, and
`notebooklm-py` on this machine already has one (ADR-0003):

```
~/.notebooklm/profiles/default/
├── storage_state.json     # the cookies. Shared. We merge, never rebuild.
└── browser_profile/       # the persistent Chromium profile. Shared.
```

If NotebookLM is not installed, everything moves to `~/.gemini-webapi/profiles/default/`.
`gemini-web auth status` always prints the resolved path and which rule produced it.

Two files sit beside the session, both ours:

```
~/.gemini-webapi/cache/.cached_cookies_<digest>.json   # rotation fast path
<profile>/.storage_state.json.lock                     # write lock, shared with notebooklm
```

## The credential ladder

The first rung that produces a session wins:

1. **Explicit** — `--cookies-json PATH`, or `GeminiClient(secure_1psid=…)`.
2. **Environment** — `GEMINI_SECURE_1PSID` / `GEMINI_SECURE_1PSIDTS`.
3. **The rotation cache** — freshest rotated token, ours.
4. **The session file** — what `gemini-web login` wrote. Shared with NotebookLM by default.
5. **A local browser's cookie database** — needs `browser-cookie3`, and often fails
   (Chrome's app-bound encryption on Windows blocks it entirely).
6. **Guest session** — no history, no model choice, no uploads. A fallback, not a session.

Rung 2 works and is flagged by `auth status` and `doctor`: environment variables are
inherited by child processes and captured by crash reporters. Prefer the session file.

## `gemini-web login`

```bash
gemini-web login                          # interactive, 5-minute patience
gemini-web login --headless               # refresh from the existing profile, no window
gemini-web login --switch-account         # allow replacing a *different* stored session
gemini-web login --channel chrome         # use installed Google Chrome instead of bundled Chromium
gemini-web login --profile work           # a second, separate session
gemini-web login --no-shared              # ignore NotebookLM's profile; use our own
```

A Chromium window opens on `https://gemini.google.com/app`. Sign in — password, 2FA,
consent screens, whatever Google asks. The window closes by itself once the session
cookie appears; there is no "click here when done" step, because the cookie jar is the
signal, not the page (ADR-0002).

What it prints:

```
Captured the Gemini session.
  cookies:  __Secure-1PSID, __Secure-1PSIDTS
  psid:     sha256:ee32ab7d
  psidts:   sha256:914ad2b7
  written:  __Secure-1PSIDTS
  file:     C:\Users\you\.notebooklm\profiles\default\storage_state.json
```

`sha256:…` is a fingerprint — a truncated digest, enough to compare sessions, useless to
replay (ADR-0005). No command in this tool prints a cookie value.

`written: nothing (already current)` means the session was confirmed rather than
changed, which is the normal result of a `--headless` refresh that finds a token that
has not rotated yet.

### What a capture is allowed to overwrite

A login **never** silently replaces one session with another. Three cases:

| The capture is… | What happens |
|---|---|
| the same session, newer rotating token | written; this is the normal refresh |
| a *different* session | refused (`mismatch`, exit 3). `--switch-account` to allow it |
| a different session, switch allowed | probed against Gemini first, and written only if it authenticates (`unverified`, exit 3, otherwise) |

That rule is not paranoia; it is a bug this tool had. A browser profile can hold a stale
`.google.com` cookie that looks perfect and authenticates as a guest, and the first
headless refresh happily wrote it over a working session. Details in ADR-0009. `--no-verify`
waives the probe if you know better than it does.

### Headless refresh

After one interactive login the browser profile holds the Google session, so:

```bash
gemini-web login --headless
```

re-runs the flow with no window and no interaction, and refreshes the rotating token.
That is the command an unattended recovery path calls.

It works when the browser profile is where the live session actually lives — true for a
profile that *this tool's* interactive login created. A profile whose session was minted
another way (NotebookLM's master-token path, for instance) can hold a stale cookie: then
the refresh reports `mismatch` and changes nothing, and the fix is one interactive
`gemini-web login`. Exit codes: `2` = no session in the profile at all, `3` = a capture
was refused, so your stored session is untouched.

## Sharing, and what it means

Because the session file is NotebookLM's too:

* **Rotations are written back.** `__Secure-1PSIDTS` rotates and the old value stops
  working, so every rotation is merged into the shared file. Without this, whichever tool
  ran last would silently log the other out (ADR-0006).
* **Nothing else in the file is touched.** NotebookLM's other 40 cookies and its
  `"notebooklm"` metadata key are preserved byte for byte.
* **One browser at a time.** Chromium locks its profile directory. `gemini-web login` while
  NotebookLM has a browser open fails to launch — close the other one.
* **An account switch is a switch for both.** One profile, one Google session.
  `gemini-web login` says so when the stored fingerprint changes.

Opt out completely:

```bash
export GEMINI_AUTH_SHARED=0     # or pass --no-shared
```

## Environment variables

| Variable | Effect |
|---|---|
| `GEMINI_HOME` | Our own home. Default `~/.gemini-webapi` |
| `GEMINI_AUTH_STORAGE` | Exact path to a `storage_state.json`; wins over everything |
| `GEMINI_AUTH_PROFILE` | Profile name. Default `default`. `--profile` sets it |
| `GEMINI_AUTH_SHARED` | `0` to stop using NotebookLM's profile |
| `GEMINI_AUTH_WRITEBACK` | `0` to stop writing rotated cookies back. See the warning in `doctor` |
| `GEMINI_COOKIE_PATH` | Rotation cache directory (upstream-compatible) |
| `GEMINI_SECURE_1PSID` / `…TS` | Cookies passed directly. Works; flagged as a risk |
| `NOTEBOOKLM_HOME` | Where NotebookLM's home is, if relocated |

## Profiles

A profile is a directory holding one session. Use one per Google account:

```bash
gemini-web --profile work login
gemini-web --profile work ask "…"
gemini-web --profile work auth status
```

Profile names are a single path segment; `../escape` is rejected rather than sanitised,
because a silently rewritten name reads one file and writes another.

## Troubleshooting

Run `gemini-web doctor` first — it checks Playwright, the session file, its cookies and
permissions, the browser profile, write-back, and the legacy cache, and prints a fix for
each failure.

| Symptom | Cause and fix |
|---|---|
| `No Gemini session found` | Nothing on any rung. `gemini-web login` |
| `Authentication failed` after weeks of working | The rotating token expired. `gemini-web login --headless`, then `gemini-web login` if that reports `no-session` |
| `no-session` from `--headless` | The browser profile's Google session is gone. One interactive `gemini-web login` |
| `mismatch` from `--headless` | The profile's cookie is for a different (often stale) session. Your stored one is untouched and probably still good; if it really has expired, run `gemini-web login` |
| `unverified` after `--switch-account` | The captured session authenticates as a guest — Google did not accept it. Sign in again in the browser window |
| Both tools report an expired session | The shared Google session itself is dead (it expires, and Google can revoke it). One interactive login restores both: `notebooklm login` writes the full cookie set, or `gemini-web login` if you only need Gemini |
| `LockTimeoutError` naming notebooklm | Another process is writing the session file. If nothing is running, a crashed process left the sentinel held — the lock is advisory, so simply retry |
| Login window never closes | The cookie never appeared. Are you signed in to *Gemini* (not just Google)? Some accounts must accept Gemini's Terms of Service in the web UI first |
| `TOS_PENDING` in `gemini-web inspect` | The account has not accepted Gemini's terms. Open <https://gemini.google.com> and accept; no cookie will fix it |
| Chromium fails to launch | Another process holds the shared browser profile, or Chromium is not installed: `python -m playwright install chromium` |
| Works, then 4xx everywhere | Google changed the web app. `git fetch upstream && git merge upstream/master` |
| Wrong Google account | `--account-index N`, or `gemini-web login` and pick the right account |

## Python API

The ladder applies to library use too — no arguments needed if a session is stored:

```python
import asyncio
from gemini_webapi import GeminiClient


async def main():
    client = GeminiClient()  # resolves the stored session
    await client.init(timeout=30, auto_refresh=True)
    print((await client.generate_content("Hello!")).text)
    await client.close()  # rotations are written back on the way out


asyncio.run(main())
```

The auth layer is public and importable when you want the pieces:

```python
from gemini_webapi.auth import resolve, status, fingerprint, LoginPlan, run_login

creds = resolve()  # Credentials | None; repr() is redacted
report = status()  # everything `auth status` prints, as a dict
result = run_login(LoginPlan.build(headless=True))
```

`docs/security.md` covers what is stored where, and what to do if a cookie leaks.
