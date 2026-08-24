"""The ``gemini-web`` command-line interface.

``from gemini_webapi.cli import main`` is the console-script entry point declared in
``pyproject.toml``; ``build_parser`` is exported because the argument surface is worth
testing on its own, without running any command.
"""

from .main import build_parser, main

__all__ = ["build_parser", "main"]
