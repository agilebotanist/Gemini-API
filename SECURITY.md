# Security policy

## Scope

This repository is a personal fork of `HanaokaYuzu/Gemini-API`, an **unofficial** client
for Gemini's web endpoints. It authenticates with Google session cookies, which are
bearer credentials for a Google account.

* Issues in the credential layer (`src/gemini_webapi/auth/`, `src/gemini_webapi/cli/`)
  belong here: <https://github.com/agilebotanist/Gemini-API/issues>
* Issues in the client itself belong upstream:
  <https://github.com/HanaokaYuzu/Gemini-API/issues>

If a report is sensitive, open an issue describing the *class* of problem without the
exploitable detail and ask for a private contact.

## Reporting

Please include: what an attacker gains, the smallest reproduction you have, and the
commit you tested. **Never paste a real cookie value into an issue** — a fingerprint
(`gemini-web auth status`) identifies a session without disclosing it.

## What this fork promises

* No command prints a cookie value — not with `--verbose`, not in `--json`, not in an
  error message. Enforced by `tests/unit/test_no_secret_leak.py`.
* Credential files are 0600 in 0700 directories, written atomically, and never named
  after their contents.
* Exactly two cookies are read, stored or transmitted: `__Secure-1PSID` and
  `__Secure-1PSIDTS`.
* Writes to a session file shared with another tool preserve everything we do not own,
  under a lock that tool also takes.

The reasoning is in `docs/security.md` (threat model, what is *not* defended) and
`docs/adr/0005-secret-hygiene.md`.

## If your session leaks

Deleting local files does not invalidate a Google session — only Google can:

1. <https://myaccount.google.com/> → Security → *Your devices* → sign out
2. `gemini-web logout --shared` and delete the browser profile directory
   (`gemini-web auth status` prints its path)
3. `gemini-web auth purge`
4. `gemini-web login`

## Supported versions

The tip of `master` on this fork. There are no backports.
