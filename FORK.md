# About this fork

This is [`agilebotanist/Gemini-API`](https://github.com/agilebotanist/Gemini-API), a fork
of [`HanaokaYuzu/Gemini-API`](https://github.com/HanaokaYuzu/Gemini-API) (`gemini-webapi`).

Upstream does the hard part: it keeps a reverse-engineered client for Gemini's web
endpoints working as Google changes them. This fork adds the part upstream is not trying
to solve — **a session that recovers by itself, and credential handling that treats
Google session cookies as secrets.**

## What is different

| | Upstream | Here |
|---|---|---|
| Getting cookies | Read another browser's cookie DB, or paste them by hand | `gemini-web login` — a real browser, a persistent profile (ADR-0002) |
| Expired session | Paste a fresh cookie | `gemini-web login --headless`, no human (ADR-0002) |
| Session storage | A temp-file cache | Playwright session file, shared with `notebooklm` (ADR-0003) |
| Cookies handled | Two (browser path), a jar elsewhere | Exactly two, enforced at the boundary (ADR-0004) |
| Cache filename | `.cached_cookies_<the raw cookie>.json` in shared temp | `.cached_cookies_<sha256>.json` under `~/.gemini-webapi` (ADR-0005) |
| Cookies in output | Printed by `--verbose` and by any traceback | Fingerprints only; scrubber as backstop (ADR-0005) |
| Rotation with two clients | Silently invalidates the other tool | Written back under a shared lock (ADR-0006) |
| CLI | `python cli.py …` | `gemini-web …` (`cli.py` still works) (ADR-0007) |
| Overwriting a session | Whatever the source says, wins | A capture must be asked for *and* verified live (ADR-0009) |
| Tests | Live, need a Google account | 246 offline tests, ~6s (ADR-0008) |

New commands: `gemini-web login`, `gemini-web logout`, `gemini-web auth status`, `gemini-web auth purge`,
`gemini-web doctor`.

Read `docs/auth.md` to use it, `docs/security.md` for what is stored where, and
`docs/adr/` for why any of it is the way it is.

## Relationship to upstream

The fork tracks upstream and expects to keep tracking it — endpoint fixes arrive there
first, and a fork that drifts is a tool that stops working.

```bash
git fetch upstream && git merge upstream/master
```

Additions live in files upstream does not have (`src/gemini_webapi/auth/`,
`src/gemini_webapi/cli/`, `docs/adr/`, `tests/unit/`), so merges stay small. Upstream's
code is changed in five places, listed in ADR-0001.

Versions are upstream's: "our build of upstream 2.x". `CHANGELOG.md` records this fork's
changes only.

## Contributing back

The auth layer is deliberately self-contained and could be offered upstream. One thing
would have to change first: sharing NotebookLM's profile directory by default is the
right call for the machine this was built for and the wrong default for a general
library — it would need to be opt-in.

## Credit

Everything that talks to Gemini is upstream's work, under upstream's licence (see
`LICENSE`). The auth layer, the CLI packaging and the docs are this fork's.
