# ADR-0001 — Fork rather than patch, and keep tracking upstream

* Status: Accepted
* Date: 2026-08-24
* Deciders: repository owner

## Context

`gemini-webapi` (HanaokaYuzu/Gemini-API) drives Gemini's web endpoints. It is good at
that, and it is not going to grow the thing this deployment needs: a login flow that
recovers from an expired session without a human, and credential handling that treats
Google session cookies as secrets.

Three ways to get there:

1. Carry local patches on top of a clone. Cheap to start, and every `git pull` is a
   conflict-resolution session with no record of intent.
2. Contribute upstream. The right long-run answer for the auth *feature*, but it
   couples our timeline to someone else's review queue, and some choices here are
   deliberately opinionated for this machine (sharing NotebookLM's profile directory)
   in a way a general-purpose library should not be.
3. Fork, and treat the fork as the artifact.

Upstream also moves fast on the part we do not want to own: the reverse-engineered
endpoints break when Google ships a change, and upstream fixes them within days. A
fork that drifts away from that stream is worse than useless — it is a tool that
silently stops working.

## Decision

Fork to `agilebotanist/Gemini-API`, and keep upstream as a first-class remote:

```
origin    → agilebotanist/Gemini-API   (ours; the skill consumes this)
upstream  → HanaokaYuzu/Gemini-API     (theirs; push disabled locally)
```

Additions live in **new files** wherever possible — the whole auth layer is
`src/gemini_webapi/auth/`, a directory upstream does not have — so a merge conflicts
only where we genuinely changed their code. Today that is five surgical edits:
`utils/logger.py` (one patcher), `utils/get_access_token.py` (one extra cookie rung),
`utils/rotate_1psidts.py` (cache path + write-back), `client.py` (a docstring), and the
CLI move.

`upstream`'s push URL is set to a bogus string locally, so a reflexive `git push
upstream` cannot happen.

## Consequences

* `git fetch upstream && git merge upstream/master` is a routine, mostly-clean
  operation, and the endpoint fixes keep arriving.
* The fork is **public**, because GitHub forks of public repositories cannot be made
  private. Nothing secret may ever be committed; ADR-0005 and the pre-commit secret
  scan exist partly for this reason.
* Upstream contribution stays open. The auth layer is self-contained enough to offer
  as a PR later; the NotebookLM-sharing default would need to become opt-in first.
* Divergence has a cost we accept: version numbers now mean "our fork's build of
  upstream's 2.x", which `FORK.md` states explicitly.

## Alternatives considered

**Vendor the library into a wrapper project.** Rejected: it makes upstream's fixes a
manual copy operation, which is the failure mode we most wanted to avoid.

**A plugin/monkey-patch package that imports upstream unmodified.** Tempting — no
merges at all — but the auth ladder lives *inside* `get_access_token`, and patching a
function's body from outside is a worse contract than a three-line diff we can read.
