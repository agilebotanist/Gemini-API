# ADR-0006 — Write rotated cookies back, under a shared lock

* Status: Accepted
* Date: 2026-08-24

## Context

`__Secure-1PSIDTS` rotates. The client POSTs `RotateCookies` every few minutes, Google
issues a fresh value, and **the previous one stops working**.

With one client that is invisible. With two clients on one session — which ADR-0003
makes the normal case — it is a bug with a nasty shape:

1. `gemini-web ask …` runs, rotates, keeps the new token in its own cache.
2. `notebooklm` starts an hour later with the token from `storage_state.json`.
3. That token was invalidated in step 1. NotebookLM reports an auth failure for a
   session the user established interactively and never touched.

The reverse happens too: NotebookLM rotated at 08:32 today, and a `gemini-web` run using a
day-old copy would have failed for the same reason.

Two clients rewriting one JSON file also race. Each does read-modify-write; without
mutual exclusion the later writer's document overwrites the earlier one's, and the
earlier one's rotation is lost — the exact failure above, from a different direction.

## Decision

**Write back.** Every rotation, and every client shutdown, merges the current
`__Secure-1PSID` / `__Secure-1PSIDTS` into the resolved session file. One choke point:
`utils/rotate_1psidts.save_cookies`, which is already the single place both events
converge. `GEMINI_AUTH_WRITEBACK=0` disables it; `gemini-web doctor` warns when it is
disabled *and* the file is shared, because that combination is the bug above waiting to
happen.

Write-back is guarded three ways:

* **Never creates a file.** A rotation must not invent a credential store, least of all
  in another tool's directory.
* **Never crosses accounts.** If the file's `__Secure-1PSID` differs from ours, the
  write is skipped: pairing our rotated token with someone else's session id produces a
  mismatched pair that authenticates as nobody.
* **Never raises.** It runs inside a background rotation task whose failure the user
  cannot see, so it degrades to "the other tool will re-login".

**Lock, compatibly.** Two properties are copied from NotebookLM rather than chosen:

| Property | Value | Why it is not ours to change |
|---|---|---|
| Sentinel path | `.storage_state.json.lock`, beside the file | Two processes that pick different sentinel names do not exclude each other. The filename *is* the contract. |
| Primitive | exclusive lock on byte 0 — `fcntl.flock` / `msvcrt.locking` | A lock only excludes another process that takes the *same* kind of lock. NotebookLM takes this one. |

A thread lock keyed on the resolved path sits in front, because `flock` is per
open-file-description: two threads in one process would each get their own and neither
would block. The sentinel file is created and **never deleted** — deleting races, since
another process can create and lock a *new* inode while the first still holds the old
one, putting two writers inside the critical section.

The whole read-modify-write happens inside the lock, so nobody can land between our
read and our write.

## Consequences

* Whichever tool rotates last, both keep working. This is what makes the shared session
  file (ADR-0003) correct rather than merely convenient.
* We write to a file another program owns. Mitigated by the merge discipline (ADR-0003),
  the atomic write (ADR-0005), the psid guard above, and tests asserting NotebookLM's
  keys and cookies survive.
* Cross-version and cross-tool compatibility now depends on a filename and a locking
  primitive, both pinned by tests — including one that compares our derivation against
  the installed NotebookLM's when it is importable.
* A wedged process holding the sentinel blocks writers for the 30-second timeout, then
  raises `LockTimeoutError` with a message naming both tools. Better than silent corruption,
  and rare enough to be worth the wait.

## Alternatives considered

**Let each tool re-login when its token dies.** Interactive re-auth as the recovery path
for a routine event. The whole point of ADR-0002 is not needing a human.

**A shared daemon owning rotation.** Correct, and vastly more machinery than two CLI
tools on one laptop justify.

**`filelock` as a dependency.** It takes the same primitive on the same byte, so it
would interoperate. Rejected for a ~60-line module: the exact byte range and the
sentinel policy are the interoperability contract, and vendoring the mechanics keeps
that visible and dependency-free.
