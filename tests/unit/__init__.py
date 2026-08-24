"""Offline unit suite: no network, no browser, no credentials.

A package (rather than loose modules) so the shared fixtures in ``_support.py`` are
importable as ``from ._support import ...`` under both ``pytest`` and
``python -m unittest discover``.
"""
