# ADR-0003 — Share NotebookLM's session file and browser profile

* Status: Accepted
* Date: 2026-08-24

## Context

This machine already runs `notebooklm-py`, which solved the same problem the same way:
a Playwright login into a persistent profile under
`~/.notebooklm/profiles/<profile>/`, with the cookies in `storage_state.json`.

Both tools authenticate to **the same Google account, with the same cookies**. A
NotebookLM session file already contains `__Secure-1PSID` and `__Secure-1PSIDTS` on
`.google.com` — exactly, and literally, what Gemini's endpoints need (verified: 43
cookies in the file, of which those two are ours).

Keeping a second, independent session would mean:

* two interactive logins for one account;
* two profiles going stale independently;
* and — the actual bug — **two rotating copies of one credential**. `RotateCookies`
  invalidates the previous `__Secure-1PSIDTS`. Whichever tool rotates first silently
  breaks the other, and the symptom is a 401 in a tool nobody was running.

## Decision

By default, `gemini-web` reads and writes NotebookLM's session file and launches from
NotebookLM's browser profile:

```
~/.notebooklm/profiles/default/storage_state.json    ← the session, shared
~/.notebooklm/profiles/default/browser_profile/      ← the Chromium profile, shared
```

Four rules make sharing safe rather than merely convenient:

1. **Join, never fabricate.** The shared rung applies only when NotebookLM's profile
   *directory already exists*. And if that directory exists but has no
   `storage_state.json` yet, `gemini-web login` writes **our own** file instead: Gemini
   needs two cookies, NotebookLM needs a dozen, and creating their file with our two
   would hand them a document that looks like a session and is not one.
2. **Preserve everything we do not own.** Writes are merges. Unknown top-level keys
   (NotebookLM keeps account metadata under `"notebooklm"`) and all other cookies are
   copied through byte for byte.
3. **Lock what we share.** Every write takes the same sentinel NotebookLM takes, with
   the same primitive (ADR-0006).
4. **Write rotations back**, so the other tool never holds a stale token (ADR-0006).

Opt out with `GEMINI_AUTH_SHARED=0` or `--no-shared`, which moves everything to
`~/.gemini-webapi/profiles/<profile>/`. Point somewhere else entirely with
`GEMINI_AUTH_STORAGE=/path/to/storage_state.json`.

The NotebookLM home is resolved by *rule*, not by importing NotebookLM: `$NOTEBOOKLM_HOME`
or `~/.notebooklm`. Duplicating two lines beats an optional import that silently changes
which file gets written depending on whether another package happens to be installed.

## Consequences

* One interactive login serves both tools, and each keeps the other's session alive.
* Coupling to a filename we do not own. `~/.notebooklm/profiles/<p>/storage_state.json`
  and the `.storage_state.json.lock` sentinel are now an interface. If NotebookLM
  relocates or renames them, sharing silently degrades to "no session found" — visible
  in `gemini-web auth status`, which prints the resolved path and its source, and in
  `gemini-web doctor`.
* Concurrency limit: only one process at a time can drive the shared browser profile
  (Chromium's own lock). `gemini-web login` while NotebookLM has a browser open fails with
  a launch error rather than corrupting anything.
* Blast radius: a bug in our write path can damage another tool's credential store.
  Mitigated by the merge discipline, the atomic write, the lock, and the tests that
  assert NotebookLM's keys and cookies survive every write path.
* An account switch in one tool is an account switch in both, since it is one browser
  profile. `gemini-web login` says so out loud when the stored fingerprint changes.

## Alternatives considered

**Separate profiles, and a documented "log in twice".** Simpler code, and it leaves the
rotation-invalidation bug in place. Rejected on correctness, not convenience.

**Copy NotebookLM's cookies into our own file at first run.** Same rotation problem, one
step later, plus a stale copy nobody remembers exists.

**Import `notebooklm.paths` when available.** Makes the resolved location depend on
whether an unrelated package is installed — the same input producing two different
target files is a debugging trap. Two lines of duplication, pinned by a test that
compares against the installed NotebookLM when there is one.
