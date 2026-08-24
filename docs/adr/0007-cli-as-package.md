# ADR-0007 — Move the CLI into the package, keep `cli.py` as a shim

* Status: Accepted
* Date: 2026-08-24

## Context

Upstream ships the CLI as `cli.py` at the repository root, with this at the top:

```python
if (_src := str(Path(__file__).resolve().parent / "src")) not in sys.path:
    sys.path.insert(0, _src)
```

That makes it runnable from a bare clone, and it means the CLI is not part of the
installed package: there is no `gemini-web` command, invocation is
`python /path/to/repo/cli.py …`, and `import cli` only works from the repository root.

The auth work needed the CLI to grow four commands (`login`, `logout`, `auth`,
`doctor`) that import the auth layer heavily. Doing that in a `sys.path`-grafted script
means the same modules can be imported under two different names depending on entry
point — the classic source of "my patch had no effect" and of duplicate module state.

## Decision

The CLI lives at `src/gemini_webapi/cli/`:

```
cli/__init__.py       # exports main, build_parser (the console-script entry point)
cli/main.py           # upstream's commands, moved with `git mv` to keep the history
cli/auth_commands.py  # login / logout / auth status / auth purge / doctor
```

`pyproject.toml` declares `gemini-web = "gemini_webapi.cli:main"`, so `pip install -e .`
gives a real `gemini-web` command.

Root `cli.py` stays as a shim that keeps the `sys.path` graft and re-exports `main` and
`build_parser`. Scripts, skill documents and upstream's own `tests/test_cli.py` invoke
the CLI by path; breaking them for a refactor they did not ask for is not a trade worth
making.

Two structural choices inside the CLI:

* **Session commands are synchronous and dispatched before the async runner.** A browser
  login has no business inside the event loop that streams model output, and `doctor`
  has to be able to run when the network client cannot start at all.
* **`--profile` is applied by exporting `GEMINI_AUTH_PROFILE` for the process.** The
  background rotation task resolves its own storage path deep inside the HTTP layer;
  threading a profile name through `GeminiClient` and `curl_cffi` to reach it would be
  a large change to upstream code for a CLI concern. One process, one profile is also
  the only sane semantics for a command invocation. Stated in the function's docstring
  because "the CLI writes to `os.environ`" is otherwise a surprise.

## Consequences

* `gemini-web login`, `gemini-web ask …` — a normal CLI, on PATH, discoverable by `--help`.
* One import path for the package, whichever entry point is used.
* `packages.find` had to become `include = ["gemini_webapi*"]`; the bare name shipped the
  top-level package only, which editable installs hide and wheels do not.
* The shim is a second entry point to keep working. It is eleven lines and covered by
  upstream's test.

## Alternatives considered

**Leave `cli.py` where it is and import the auth layer through the graft.** Zero
migration, and it keeps the dual-import-name hazard and gives no `gemini-web` command.

**`python -m gemini_webapi` instead of a console script.** Works, no entry-point
metadata, worse ergonomics for a tool that also gets invoked from skill documents.
