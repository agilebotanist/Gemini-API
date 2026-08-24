---
name: gemini-api
description: |
  Drive the Google Gemini web app from the CLI via the gemini-webapi fork — ask
  questions, continue chats, run Deep Research, list models, download generated
  images. Handles its own auth: `gemini-web login` opens a browser once, then refreshes
  the session unattended. Use when the user asks to query Gemini, get a second
  opinion from another model, run "deep research" on a topic, or mentions
  gemini-webapi / Gemini-API. Prefer this over a web search when the task wants a
  reasoned synthesis rather than a list of links.
---

# Gemini (unofficial web-app client)

Drives the **Gemini web app** with a real Google session — not the official Google AI
API. You get the web experience (Deep Research, Gems, image generation) programmatically,
without an API key.

This is a fork of [HanaokaYuzu/Gemini-API](https://github.com/HanaokaYuzu/Gemini-API)
that adds the auth layer; see `FORK.md` and `docs/adr/`.

## What it costs you

| | |
|---|---|
| **Auth** | A Google session, captured by a browser login you do once |
| **Key needed** | None |
| **Official?** | **No.** Reverse-engineered web endpoints |
| **Stability** | Breaks when Google changes the web app — `git fetch upstream && git merge upstream/master` |
| **Rate limits** | Whatever the web UI enforces on the account |

A convenience tool for research and second opinions, not infrastructure. For anything
that must not break, use the official Google AI SDK with a real API key.

## First run

```bash
gemini-web login            # a Chromium window opens; sign in to Google
gemini-web auth status      # confirm: source, fingerprints, expiry
gemini-web models           # confirm the account can reach models
```

`gemini-web login` is needed **once**. After that the browser profile holds the session and
`gemini-web login --headless` refreshes the rotating cookie with no window and no
interaction — that is the command to run first when a request suddenly fails with an auth
error.

A refresh never overwrites a *different* session than the stored one: it reports
`mismatch` (exit 3) and changes nothing, because a browser profile can hold a stale
cookie that would replace a working credential with a guest session (ADR-0009). If that
happens and the stored session really is dead, run the interactive `gemini-web login`.

On this machine the session is **shared with `notebooklm`** (same Google account, same
cookies): one login serves both, and each keeps the other's session alive. Details and
opt-out in `docs/auth.md`.

## Commands

| Task | Command |
|------|---------|
| Ask a single question | `gemini-web ask "question"` |
| Ask without streaming | `gemini-web ask --no-stream "question"` |
| Ask about an image | `gemini-web ask --image path.png "what does this show?"` |
| Continue a chat | `gemini-web reply <c_chat_id> "follow-up"` |
| List chats | `gemini-web list` |
| Read a chat | `gemini-web read <c_chat_id> --max-turns 20 --output chat.md` |
| List models | `gemini-web models` |
| Pick a model | `gemini-web --model <name\|alias\|id> ask "…"` |
| Download a generated image | `gemini-web download <url> -o image.png` |
| Account probe (quota, status) | `gemini-web inspect` |
| Session state | `gemini-web auth status` |
| Diagnose auth | `gemini-web doctor` |

Global flags: `--verbose`, `--proxy`, `--account-index N`, `--profile NAME`,
`--no-shared`, `--cookies-json PATH`, `--request-timeout N`.

If `gemini-web` is not on PATH (no editable install), every command also works as
`python <repo>/cli.py …`.

## Deep Research

Asynchronous, and the reason this skill is worth having. Submit, poll, collect:

```bash
# 1. Submit — returns a chat id (c_...)
gemini-web research send --prompt "Evidence on software effort estimation accuracy since 2015"

# 2. Poll — takes minutes, not seconds
gemini-web research check <c_chat_id>

# 3. Collect
gemini-web research get <c_chat_id> --output research.md
```

Don't block on step 2 in a tight loop. Submit, do other work, come back. For a long run,
hand the polling to a background agent.

## Research discipline: output is a lead, never a citation

Gemini Deep Research paraphrases and attributes loosely. For literature work
(MSDBOK/MSD, SQR, any citation-bearing output) it is a **scoping** tool:

1. Take the claims and named works it surfaces
2. Resolve each to a real record in Semantic Scholar / CrossRef
3. Read the actual source — via `/pdf2md`, never a PDF directly
4. Only then write it into `summaries/` or a handbook page

Verify every quote with WebSearch, and cite the primary source, not a model's summary of
it. Management literature is full of misattributed aphorisms and contested numbers
(Standish CHAOS, Brooks's law variants) that an LLM will repeat confidently.

| Tool | Good for |
|------|----------|
| Paper Search MCP | Real bibliographic records — DOIs, citation counts, PDFs |
| Gemini Deep Research | Fast orientation, cross-source synthesis in prose |
| NotebookLM (`/notebooklm`) | Grounded answers over sources **you** chose |

## Python API

```python
import asyncio
from gemini_webapi import GeminiClient


async def main():
    client = GeminiClient()  # resolves the stored session; no arguments needed
    await client.init(timeout=30, auto_refresh=True)
    print((await client.generate_content("Hello World!")).text)
    await client.close()


asyncio.run(main())
```

`generate_content` returns a `ModelOutput` with `.text`, `.images`, `.thoughts` and
conversation metadata. The full surface — multi-turn chats, Gems, image generation and
editing, video/audio, extensions, streaming, temporary mode — is in `README.md`
(upstream's, ~35 KB, current with the code). Read it rather than guessing.

The auth layer is importable too:

```python
from gemini_webapi.auth import resolve, status, LoginPlan, run_login
```

## Troubleshooting

Run `gemini-web doctor` first; it names the fix for each failure.

| Symptom | Cause / fix |
|---------|-------------|
| `No Gemini session found` | `gemini-web login` |
| `UNAUTHENTICATED` from every command | The shared Google session is dead. One interactive login fixes both tools: `notebooklm login` (full cookie set) or `gemini-web login` |
| Auth failure after weeks of working | Session expired: `gemini-web login --headless`, then `gemini-web login` if that reports `no-session` or `mismatch` |
| `TOS_PENDING` / API error 1040 on every prompt | The account has not accepted Gemini's Terms of Service. Open <https://gemini.google.com> in a browser and accept — no cookie fixes this |
| Login window never closes | Not actually signed in to Gemini, or a consent screen is waiting |
| Chromium won't launch | `notebooklm` has the shared browser profile open — close it; or `python -m playwright install chromium` |
| `ModuleNotFoundError: gemini_webapi` | `pip install -e ".[playwright,browser]"` in the repo |
| Works then suddenly 4xx everywhere | Google changed the web app: `git fetch upstream && git merge upstream/master` |
| Deep Research never completes | Normal runs take minutes; re-`check` before assuming failure |
| Wrong Google account | `--account-index N`, or `gemini-web login` and pick the account |

## Documentation map

| File | Contents |
|------|----------|
| `docs/auth.md` | Sessions, profiles, sharing, every environment variable |
| `docs/security.md` | Threat model, what is stored where, what to do if a cookie leaks |
| `docs/development.md` | Tests, lint, layout, working with upstream |
| `docs/adr/` | Why the auth layer is the way it is (8 decisions) |
| `FORK.md` | What this fork changed and why |
| `README.md` | Upstream's full client documentation |
