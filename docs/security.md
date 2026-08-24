# Security

What this fork holds, where it puts it, what it promises, and what it cannot promise.

## What is at stake

`__Secure-1PSID` is a **bearer credential for a Google account**. Whoever holds it can
use the Gemini web app as that account until Google expires it. `__Secure-1PSIDTS` is
its rotating companion — shorter-lived, and useless without the first.

There is no way to avoid holding them: the endpoints accept nothing else (ADR-0002).
So the design question is not encryption, it is **exposure surface**.

## Threat model

Defended:

| Threat | Control |
|---|---|
| Another user on the host reads the credential | Session file and cache are 0600 in 0700 directories; `doctor` audits |
| Another user *lists* the credential | Cache filenames are SHA-256 digests, never values (ADR-0005) |
| A credential lands in a log, a terminal, a CI transcript | Fingerprints on every human-visible surface; loguru scrubber as backstop |
| A credential lands in a traceback from a dependency | Process-wide secret registry + `scrub()`, including shape-based patterns |
| A credential is committed to the (public) fork | `.gitignore` entries, a `gitleaks` pre-commit hook, and a CI secret scan |
| A crash mid-write destroys the session | Atomic write: temp file `O_EXCL` 0600, then `os.replace` |
| Two writers lose one's rotation | Cross-process lock, byte-compatible with `notebooklm` (ADR-0006) |
| Over-broad credential handling | Two-cookie allowlist; everything else dropped at the boundary (ADR-0004) |
| Header injection through a hand-edited cookie file | Values containing CR/LF/NUL/TAB/`;` are rejected |
| Path traversal through a profile name | Single-segment names only; `../` rejected, not sanitised |

Not defended — and no library can:

* **Malware or another process running as you.** It can read your files, your
  environment, and your browser profile. Same trust boundary as your SSH key.
* **A compromised host, disk theft, or a backup.** The session file is plaintext JSON, by
  necessity — see the keyring discussion in ADR-0005.
* **Google's own view of the traffic.** This is your session, used from your machine.
* **The Gemini web app itself.** Reverse-engineered endpoints, no stability contract.

## Where credentials are stored

| Path | Contents | Mode |
|---|---|---|
| `<profile>/storage_state.json` | `__Secure-1PSID`, `__Secure-1PSIDTS` (+ whatever another tool put there) | 0600 |
| `<profile>/browser_profile/` | A full Chromium profile with a live Google session | Chromium's own |
| `~/.gemini-webapi/cache/.cached_cookies_<digest>.json` | The HTTP session's working cookie set | 0600 in 0700 |
| `<profile>/.storage_state.json.lock` | Empty sentinel | 0600 |

Note the second row honestly: the **browser profile is the most sensitive artifact
here**. It holds a signed-in Google session for the whole account, not just the two
cookies we handle. It is what makes unattended refresh possible (ADR-0002), and deleting
it is the only way to be sure the session is gone locally.

On Windows, POSIX mode bits are synthetic. The controls there are the per-user
`%USERPROFILE%` ACL and `%TEMP%`; `gemini-web doctor` reports permissions rather than
asserting them, because a Windows `stat().st_mode` says nothing true about the ACL.

## What the tool prints

Fingerprints: `sha256:` plus 8 hex characters of the digest. Enough to answer "same
session?" and "did it change?", useless to replay. `-` means absent.

```
  __Secure-1PSID:   sha256:ee32ab7d  expires 2028-08-23T08:27:06Z
```

No command prints a cookie value — not with `--verbose`, not in `--json`, not in an
error. `tests/unit/test_no_secret_leak.py` enforces this from the outside: a known
cookie goes into a session file, every command and object repr is rendered, and the
output is searched for the value, its prefix and its URL-encoded form.

## Using environment variables

`GEMINI_SECURE_1PSID` works and is reported as a risk by `auth status` and `doctor`.
Environment variables are inherited by every child process, are visible in some process
listings, and are captured verbatim by crash reporters and CI logs. Prefer a session
file; if you must use the environment (containers, CI), scope it to the one process and
never echo it.

## If a cookie leaks

1. **Sign out server-side.** <https://myaccount.google.com/> → Security → *Your devices*
   → sign out. Deleting local files does not invalidate the session; only Google can.
   `gemini-web logout` says so.
2. Then clean locally: `gemini-web logout --shared`, and delete the browser profile
   directory (`gemini-web auth status` prints its path).
3. `gemini-web auth purge` to remove any pre-fork cache files.
4. `gemini-web login` to establish a fresh session.
5. If the leak was into a git repository, rotating the credential (step 1) is the fix —
   rewriting history is not, because the value is public the moment it is pushed.

## Reporting a vulnerability

This is a personal fork of an unofficial client. Open an issue at
<https://github.com/agilebotanist/Gemini-API/issues> — or, if the report itself is
sensitive, describe the class of problem without the details and ask for a contact.

If the issue is in upstream's code rather than the auth layer, it belongs at
<https://github.com/HanaokaYuzu/Gemini-API/issues>.

## For reviewers

The whole credential surface is eight files, ~1,200 lines, in
`src/gemini_webapi/auth/`. Reading order:

1. `paths.py` — every location, every environment variable
2. `redaction.py` — fingerprints and scrubbing
3. `cookie_policy.py` — the allowlist and row sanitisation
4. `storage_state.py` — atomic, locked, merge-preserving writes
5. `locking.py` — the cross-tool lock
6. `writeback.py`, `resolver.py`, `playwright_login.py` — the flows

Plus five small edits to upstream's code, listed in ADR-0001.
