#!/usr/bin/env python3
"""Compatibility shim: ``python cli.py …`` still works.

The CLI moved into the package (``gemini_webapi.cli``) so it could install as a real
console script and import the auth layer as a sibling — see ADR-0007. This file stays
because scripts, skills and docs in the wild invoke the CLI by path, and breaking those
for a refactor they did not ask for is not a trade worth making.

Prefer the installed entry point:

    gemini ask "hello"

which is what ``pip install -e .`` provides.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Running from a source checkout, the package may not be installed. Add `src` so the
# shim works in a bare clone exactly as the old script did.
if (_src := str(Path(__file__).resolve().parent / "src")) not in sys.path:
    sys.path.insert(0, _src)

from gemini_webapi.cli import build_parser, main  # placed after the sys.path graft, by design

# `build_parser` is re-exported because upstream's own test suite imports it from here.
__all__ = ["build_parser", "main"]

if __name__ == "__main__":
    raise SystemExit(main())
