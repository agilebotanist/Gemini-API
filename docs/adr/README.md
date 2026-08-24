# Architecture decisions

This fork records the decisions that shaped it, so that the *why* survives the people
and the chat sessions that produced it. Format is [MADR](https://adr.github.io/madr/)
trimmed to what earns its keep: context, decision, consequences, and the alternatives
that were actually considered.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-fork-and-track-upstream.md) | Fork rather than patch, and keep tracking upstream | Accepted |
| [0002](0002-playwright-login.md) | Make a real browser login the primary auth path | Accepted |
| [0003](0003-share-the-notebooklm-profile.md) | Share NotebookLM's session file and browser profile | Accepted |
| [0004](0004-minimum-cookie-set.md) | Handle exactly two cookies | Accepted |
| [0005](0005-secret-hygiene.md) | Fingerprints everywhere, values nowhere | Accepted |
| [0006](0006-writeback-and-locking.md) | Write rotated cookies back, under a shared lock | Accepted |
| [0007](0007-cli-as-package.md) | Move the CLI into the package, keep `cli.py` as a shim | Accepted |
| [0008](0008-offline-test-strategy.md) | Test the decisions, not the browser | Accepted |
| [0009](0009-verify-before-replacing-a-session.md) | A capture must earn the right to replace a stored session | Accepted |

## When to add one

Write an ADR when a choice is (a) hard to reverse, (b) surprising to a reader of the
code, or (c) something a future maintainer might "fix" without knowing why it is the
way it is. The lock filename in ADR-0006 is the archetype: two words of code, and
changing them silently breaks a guarantee.

Number sequentially, never renumber, and supersede rather than edit an accepted one —
`Status: Superseded by ADR-00NN`. The value of the record is that it is what we thought
at the time.
