# Development

## Setup

```bash
git clone https://github.com/agilebotanist/Gemini-API
cd Gemini-API
pip install -e ".[playwright,browser,dev]"
python -m playwright install chromium
```

`pip install -e .` also puts the `gemini-web` command on PATH.

## Tests

```bash
pytest                              # the offline suite (default), ~4s, 229 tests
pytest tests/unit/test_paths.py -v  # one module
pytest tests/test_client_features.py   # LIVE: hits gemini.google.com with your session
```

The default target is `tests/unit` — hermetic: no network, no browser, no credentials,
no writes outside a temp directory (ADR-0008). Upstream's live tests are run
deliberately, by path; they authenticate through whatever session the ladder finds, so
they are neither fast nor repeatable.

Writing a test that touches the auth layer:

```python
from ._support import FAKE_PSID, IsolatedHome


def test_something(self):
    with IsolatedHome() as home:
        home.write_storage(home.shared_storage())  # or .own_storage()
        ...
```

`IsolatedHome` redirects *every* auth environment variable at once. Never let a test
resolve a real path — a missed variable means the test silently exercises the
developer's own `~/.notebooklm`, and the first symptom is a corrupted personal session.

For the login flow, inject a browser instead of launching one:

```python
context = FakeContext(cookie_schedule=[[], SIGNED_IN])  # signed out, then signed in
result = run(login.capture(plan, launcher=fake_launcher(context)))
```

Use the fixtures' cookie values (`FAKE_PSID`, `FAKE_PSIDTS`). They carry the `g.a0`
prefix and the length of real ones, which is what the scrubber's heuristics key on; a
test using `"secret123"` passes while the shipped code leaks.

## Lint and types

```bash
uvx ruff check . && uvx ruff format --check .
uvx pyright src        # optional; upstream's config, "standard" mode
```

Upstream's `ruff` configuration (line length 100, a broad rule set) applies unchanged.

## Layout

```
src/gemini_webapi/
├── auth/              ← this fork's addition. Everything credential-shaped.
│   ├── paths.py            locations + env-var names
│   ├── redaction.py        fingerprints, scrubbing
│   ├── cookie_policy.py    allowlist, row sanitisation
│   ├── locking.py          cross-process lock (shared with notebooklm)
│   ├── storage_state.py    session file read/merge/atomic write
│   ├── writeback.py        rotated cookies → session file
│   ├── resolver.py         the credential ladder + status report
│   └── playwright_login.py interactive login + headless refresh
├── cli/               ← moved here from root cli.py (ADR-0007)
│   ├── main.py             upstream's commands
│   └── auth_commands.py    login / logout / auth / doctor
├── client.py          ← upstream, one docstring changed
├── utils/             ← upstream, three surgical edits
└── ...                ← upstream, untouched
cli.py                 ← compatibility shim
docs/adr/              ← why any of this is the way it is
```

## Working with upstream

```bash
git fetch upstream
git merge upstream/master
pytest && uvx ruff check .
```

Conflicts should be rare and small — the auth layer is in files upstream does not have.
The five places we changed their code are listed in ADR-0001; if a merge touches one,
read the ADR before resolving.

`git push upstream` is disabled locally (its push URL is a bogus string). Push to
`origin`.

## Conventions

**Docstrings carry the why.** The auth layer is full of choices that look arbitrary and
are not — the lock filename, the two-cookie allowlist, the "join, never fabricate" rule
for shared profiles. Each one says why in place, and points at its ADR. If you find
yourself writing "this is required" without a reason, the reason is what the next reader
needs.

**New credential path? Add it to `paths.py`.** Not to the module that needs it. The
value of one file holding every location is that it is one file to audit.

**New printed field? Print a fingerprint.** And if it is a new *kind* of surface, add it
to `test_no_secret_leak.py`, which is what makes the guarantee structural rather than
aspirational.

**Decisions get an ADR.** Sequentially numbered in `docs/adr/`, superseded rather than
edited. See `docs/adr/README.md` for the bar.
